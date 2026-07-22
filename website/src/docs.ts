import type { Page } from "./types";

/**
 * Documentation content model.
 *
 * The docs section is a small, self-contained documentation site: an ordered
 * set of pages grouped into sidebar sections. Each page is a list of blocks
 * (headings, prose, code, callouts, lists, link cards) that the Docs renderer
 * turns into an article plus an auto-generated "On this page" table of
 * contents (built from the `h` blocks).
 */

export interface DocCard {
  title: string;
  body: string;
  to: Page;
}

export type DocBlock =
  | { type: "h"; id: string; text: string }
  | { type: "p"; text: string }
  | { type: "list"; items: string[] }
  | { type: "code"; caption?: string; code: string }
  | { type: "note"; text: string }
  | { type: "warn"; text: string }
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "cards"; cards: DocCard[] };

export interface DocPage {
  slug: string;
  section: string;
  navLabel: string;
  title: string;
  intro: string;
  blocks: DocBlock[];
}

export interface DocSectionGroup {
  label: string;
  slugs: string[];
}

export const DOC_SECTIONS: DocSectionGroup[] = [
  { label: "Getting started", slugs: ["quickstart", "installation", "concepts"] },
  {
    label: "Platform",
    slugs: [
      "auth",
      "authz",
      "grpc",
      "oauth2",
      "federation",
      "pki",
      "webhooks",
      "audit",
    ],
  },
  { label: "Operate", slugs: ["deploy", "configuration", "sdks"] },
];

export const DOC_PAGES: DocPage[] = [
  {
    slug: "quickstart",
    section: "Getting started",
    navLabel: "Quickstart",
    title: "Quickstart",
    intro:
      "Get a local AXIAM instance running, then make your first authenticated authorization check.",
    blocks: [
      { type: "h", id: "prereq", text: "Prerequisites" },
      {
        type: "p",
        text: "AXIAM builds with Rust 1.93+ and runs its dev infrastructure (SurrealDB + RabbitMQ) via Docker. The `just` task runner wraps the common commands.",
      },
      { type: "h", id: "run", text: "Run the stack" },
      {
        type: "code",
        code: "# start dev infrastructure (SurrealDB + RabbitMQ)\njust dev-up\n\n# build, then run the full test suite\njust build\njust test",
      },
      { type: "h", id: "authz", text: "Your first authorization check" },
      {
        type: "p",
        text: "Install a client SDK, construct a client for your tenant, sign in, then call `can()`. Tenant is always explicit — AXIAM is multi-tenant with no default tenant.",
      },
      {
        type: "code",
        caption: "quickstart · TypeScript",
        code: "import { AxiamClient } from 'axiam-sdk';\n\nconst axiam = new AxiamClient({\n  baseUrl: 'https://iam.acme.dev',\n  tenantSlug: 'acme',\n  orgSlug: 'acme',\n});\n\nawait axiam.login(email, password);\nconst ok = await axiam.can('read', 'doc:1');",
      },
      {
        type: "note",
        text: "Tokens arrive only via `httpOnly` cookies — CSRF forwarding and single-flight refresh are handled for you. Browser code imports only from `axiam-sdk/rest`.",
      },
      { type: "h", id: "next", text: "Next steps" },
      {
        type: "cards",
        cards: [
          {
            title: "Browse the SDKs →",
            body: "Quickstarts for all eleven languages.",
            to: "sdks",
          },
          {
            title: "See the benchmarks →",
            body: "Performance, efficiency and security posture.",
            to: "bench",
          },
        ],
      },
    ],
  },

  {
    slug: "installation",
    section: "Getting started",
    navLabel: "Installation",
    title: "Installation",
    intro:
      "Everything you need to build AXIAM from source and stand up its backing services for local development.",
    blocks: [
      { type: "h", id: "toolchain", text: "Toolchain" },
      {
        type: "p",
        text: "AXIAM is a Cargo workspace of focused crates — `axiam-core`, `axiam-db`, `axiam-auth`, `axiam-authz`, the API crates and `axiam-server`, which composes them into the runnable binary. You need a Rust 1.93+ toolchain, Docker (for SurrealDB and RabbitMQ), and the `just` task runner.",
      },
      {
        type: "code",
        caption: "install the task runner",
        code: "# macOS\nbrew install just\n\n# or via cargo, anywhere\ncargo install just",
      },
      { type: "h", id: "services", text: "Backing services" },
      {
        type: "p",
        text: "`just dev-up` starts the development infrastructure in Docker: a SurrealDB node (the document/graph store for every domain entity) and a RabbitMQ broker (used for async authorization, audit ingestion and event notifications). `just dev-down` stops them again.",
      },
      {
        type: "code",
        code: "just dev-up      # start SurrealDB + RabbitMQ\njust dev-down    # stop them",
      },
      { type: "h", id: "build", text: "Build & verify" },
      {
        type: "p",
        text: "Build the workspace and run the checks. `just check` runs formatting, lints and the test suite together — the same gate CI enforces on every commit.",
      },
      {
        type: "code",
        code: "just build       # compile the workspace\njust test        # run all tests\njust check       # fmt + lint + test",
      },
      {
        type: "note",
        text: "Each roadmap task lands as a signed commit, and `just check` must be green before the next one begins. See the Roadmap for the full 19-phase breakdown.",
      },
    ],
  },

  {
    slug: "concepts",
    section: "Getting started",
    navLabel: "Core concepts",
    title: "Core concepts",
    intro:
      "The domain model AXIAM is built around — organizations, tenants, and the entities scoped inside them.",
    blocks: [
      { type: "h", id: "tenancy", text: "Organizations & tenants" },
      {
        type: "p",
        text: "Organizations are the top-level entities: they hold the CA certificates and contain one or more tenants. A tenant provides full data isolation — its own users, groups, roles, permissions, resources, certificates and configuration. There is no default tenant; every SDK call carries an explicit tenant.",
      },
      { type: "h", id: "identity", text: "Identities" },
      {
        type: "list",
        items: [
          "Users authenticate via username/password, social login, MFA or certificates.",
          "Groups are named collections of users; roles assigned to a group are inherited by all members.",
          "Service accounts are used for automated, machine-to-machine authentication.",
        ],
      },
      { type: "h", id: "access", text: "Roles, permissions & resources" },
      {
        type: "p",
        text: "Permissions define actions on resources, and scopes provide sub-resource granularity. Roles are collections of permissions and can be global or resource-specific. Resources are organized hierarchically: a role assigned on a parent resource cascades to its children unless a more specific assignment overrides it.",
      },
      {
        type: "note",
        text: "The authorization engine is additive-only — allow-wins with default-deny. There is no explicit deny-override in the current release; the deny-override cascade is deferred to a later version.",
      },
    ],
  },

  {
    slug: "auth",
    section: "Platform",
    navLabel: "Authentication & MFA",
    title: "Authentication & MFA",
    intro:
      "How AXIAM verifies identity: password hashing, short-lived tokens, rotating refresh tokens and multi-factor authentication.",
    blocks: [
      { type: "h", id: "passwords", text: "Passwords" },
      {
        type: "p",
        text: "Passwords are hashed with Argon2id using OWASP-recommended parameters. AXIAM never stores or logs a plaintext credential, and SDKs wrap secrets in redacting types so they don't leak into logs or error messages.",
      },
      { type: "h", id: "tokens", text: "Tokens" },
      {
        type: "list",
        items: [
          "Access tokens are JWTs signed with EdDSA (Ed25519) and are short-lived — 15 minutes.",
          "Refresh tokens are opaque, server-stored and single-use, rotating on every refresh.",
          "In the browser, tokens live only in `httpOnly` cookies; the SDK handles CSRF forwarding and single-flight refresh for you.",
        ],
      },
      { type: "h", id: "mfa", text: "Multi-factor authentication" },
      {
        type: "p",
        text: "MFA is built in, starting with TOTP and designed to extend to WebAuthn. MFA secrets are encrypted at rest with AES-256-GCM. When a step-up is required, the SDK surfaces an MFA challenge that you complete before the session is fully established.",
      },
      {
        type: "code",
        caption: "login with a TOTP step-up",
        code: "await axiam.login(email, password);\n\nif (axiam.mfaRequired) {\n  await axiam.submitTotp(code);\n}",
      },
    ],
  },

  {
    slug: "authz",
    section: "Platform",
    navLabel: "Authorization engine",
    title: "Authorization engine",
    intro:
      "The RBAC core: additive, allow-wins evaluation over a cascading resource hierarchy, reachable over three protocols.",
    blocks: [
      { type: "h", id: "model", text: "The evaluation model" },
      {
        type: "p",
        text: "Authorization is role-based and additive. Evaluation is allow-wins with default-deny: if any role grants the requested permission on the resource (or an ancestor it inherits from), the decision is allow; otherwise it is deny. This keeps decisions fast and predictable.",
      },
      { type: "h", id: "hierarchy", text: "Hierarchy & scopes" },
      {
        type: "p",
        text: "Resources form a tree. Role assignments on a parent cascade to descendants, so you grant broadly at the top and refine below. Scopes add sub-resource granularity when a permission needs to apply to only part of a resource.",
      },
      { type: "h", id: "checks", text: "Making a check" },
      {
        type: "p",
        text: "Every SDK exposes the same `can(action, resource)` call. Under the hood it can run over REST for standard requests, gRPC for low-latency checks inside a service mesh, or AMQP for deferred/async decisions — all backed by one engine.",
      },
      {
        type: "code",
        code: "// synchronous check\nconst ok = await axiam.can('read', 'doc:1');\n\n// batch several checks in one round trip\nconst results = await axiam.canAll([\n  ['read', 'doc:1'],\n  ['write', 'doc:1'],\n]);",
      },
    ],
  },

  {
    slug: "grpc",
    section: "Platform",
    navLabel: "gRPC API",
    title: "gRPC API",
    intro:
      "A low-latency gRPC surface for service-mesh authorization checks, token validation and user lookups — backed by Tonic and one protobuf contract shared across every SDK.",
    blocks: [
      { type: "h", id: "why", text: "Why gRPC" },
      {
        type: "p",
        text: "REST is the general-purpose surface; gRPC exists for the hot path. Inside a service mesh, sidecars and backends make authorization checks on nearly every request, where connection reuse and binary framing keep tail latency low. In the benchmark run, AXIAM's single gRPC `CheckAccess` held a p99 of 90 ms at database saturation and served TLS 1.3 with no measurable penalty versus plaintext.",
      },
      { type: "h", id: "services", text: "Services" },
      {
        type: "p",
        text: "Three services are defined in `proto/axiam/v1/`. Every request message is tenant-scoped — `tenant_id` is a field on every RPC, because AXIAM is multi-tenant with no default tenant.",
      },
      {
        type: "table",
        headers: ["Service", "RPCs", "Purpose"],
        rows: [
          [
            "AuthorizationService",
            "CheckAccess, BatchCheckAccess",
            "Single access check, or several checks in one round-trip.",
          ],
          [
            "TokenService",
            "ValidateToken, IntrospectToken",
            "Signature + expiry validation, or full RFC 7662-style claims.",
          ],
          [
            "UserService",
            "GetUser, ValidateCredentials",
            "Lookup by ID, or a username/password check that issues no token.",
          ],
        ],
      },
      { type: "h", id: "server", text: "The server" },
      {
        type: "p",
        text: "The gRPC server starts inside `axiam-server` alongside the REST and AMQP listeners. It binds to `127.0.0.1:50051` by default — loopback only — and is meant to be reached in-cluster over an internal network or mTLS, never exposed through a public ingress. Configure the bind address, port and per-IP rate limit with the `AXIAM__GRPC__*` environment variables (see Configuration).",
      },
      {
        type: "note",
        text: "In the Kubernetes manifests, gRPC (port 50051) is intentionally *not* routed through the Ingress — it is reachable only via the in-cluster `axiam-server` ClusterIP service.",
      },
      { type: "h", id: "consume", text: "Consuming the API" },
      {
        type: "p",
        text: "The seven full SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) ship pre-generated client stubs, so you consume gRPC without running codegen yourself. Tenant is always explicit, and the call surface mirrors the REST `can()` / `canAll()` you already know.",
      },
      {
        type: "code",
        caption: "authorization check over gRPC · Rust",
        code: 'use axiam_sdk::AxiamClient;\n\nlet axiam = AxiamClient::builder()\n    .base_url("https://iam.acme.dev")\n    .tenant_slug("acme")\n    .org_slug("acme")\n    .grpc(true) // route checks over the gRPC transport\n    .build()?;\n\nlet ok = axiam.can("read", "doc:1").await?;',
      },
      { type: "h", id: "codegen", text: "Generating your own stubs" },
      {
        type: "p",
        text: "If you integrate from a language without a published AXIAM SDK, generate stubs directly from the `.proto` files with `buf generate` (or `protoc` plus your language's gRPC plugin). The files are self-contained proto3 with no external imports beyond the well-known types, and a CI job runs `buf lint` and `buf breaking` against them on every change, so the contract is guarded against accidental breakage.",
      },
      {
        type: "code",
        code: "# generate client stubs from the vendored proto/ tree\nbuf generate",
      },
      {
        type: "note",
        text: "The Kotlin, Swift, C and C++ SDKs cover the REST surface today; gRPC is a planned follow-up for them. Until it lands, use the REST transport or generate stubs directly from `proto/`.",
      },
    ],
  },

  {
    slug: "oauth2",
    section: "Platform",
    navLabel: "OAuth2 & OIDC",
    title: "OAuth2 & OpenID Connect",
    intro:
      "AXIAM is a full OAuth2 authorization server and OpenID Connect provider.",
    blocks: [
      { type: "h", id: "flows", text: "Supported flows" },
      {
        type: "list",
        items: [
          "Authorization Code with PKCE — for browser and mobile apps.",
          "Client Credentials — for machine-to-machine access with service accounts.",
          "Refresh Token — with opaque, single-use rotation.",
        ],
      },
      { type: "h", id: "oidc", text: "OpenID Connect" },
      {
        type: "p",
        text: "On top of OAuth2 authorization, OIDC provides authentication and identity: ID tokens, a userinfo endpoint and standard discovery. Access tokens are the same short-lived EdDSA-signed JWTs used across the platform.",
      },
      { type: "h", id: "discovery", text: "Discovery" },
      {
        type: "p",
        text: "Each tenant exposes a standards-compliant discovery document, so off-the-shelf OAuth2/OIDC clients can configure themselves against an AXIAM tenant with just the issuer URL.",
      },
      {
        type: "code",
        caption: "per-tenant discovery",
        code: "GET https://iam.acme.dev/acme/.well-known/openid-configuration",
      },
    ],
  },

  {
    slug: "federation",
    section: "Platform",
    navLabel: "Federation",
    title: "Federation",
    intro:
      "Cross-domain single sign-on: AXIAM acts as a SAML service provider and an OIDC federation client.",
    blocks: [
      { type: "h", id: "why", text: "Why federate" },
      {
        type: "p",
        text: "Federation lets users from an external identity provider sign in to an AXIAM tenant without a separate local credential. AXIAM supports both SAML and OpenID Connect as upstream protocols, so it slots into existing enterprise SSO.",
      },
      { type: "h", id: "saml", text: "SAML" },
      {
        type: "p",
        text: "As a SAML service provider, AXIAM consumes assertions from an external IdP, validates the signature and maps assertion attributes onto tenant identities, groups and roles.",
      },
      { type: "h", id: "oidc-fed", text: "OIDC federation" },
      {
        type: "p",
        text: "As an OIDC federation client, AXIAM delegates authentication to an upstream provider, then issues its own tenant-scoped session. Attribute and claim mapping is configured per tenant.",
      },
      {
        type: "note",
        text: "Federated identities live inside a tenant like any other user, so roles, permissions and audit apply to them uniformly.",
      },
    ],
  },

  {
    slug: "pki",
    section: "Platform",
    navLabel: "PKI & certificates",
    title: "PKI & certificates",
    intro:
      "Per-tenant X.509 certificate management, signed by the organization CA, for users, services and IoT devices.",
    blocks: [
      { type: "h", id: "hierarchy", text: "Certificate hierarchy" },
      {
        type: "p",
        text: "Certificates are managed per tenant and signed by the organization's CA. They use RSA-4096 or Ed25519 keys. Private keys are never stored server-side — they are returned exactly once at issuance, and CA signing keys are themselves encrypted at rest with AES-256-GCM.",
      },
      { type: "h", id: "mtls", text: "mTLS for devices" },
      {
        type: "p",
        text: "Certificate-based authentication enables mutual TLS for IoT devices and services, giving machine identities the same tenant-scoped authorization as human users. TLS 1.3 is the minimum for all external communication.",
      },
      { type: "h", id: "gnupg", text: "GnuPG integration" },
      {
        type: "p",
        text: "OpenPGP keys, managed through the PKI layer, are used to sign the audit trail and to encrypt data exports — so exported data and audit records are verifiable and confidential end to end.",
      },
    ],
  },

  {
    slug: "webhooks",
    section: "Platform",
    navLabel: "Webhooks",
    title: "Webhooks",
    intro:
      "Real-time event delivery to external systems, with signatures downstream consumers can verify.",
    blocks: [
      { type: "h", id: "delivery", text: "Signed delivery" },
      {
        type: "p",
        text: "Webhooks deliver event notifications to external endpoints as they happen. Every payload is signed with HMAC-SHA256, so a receiver can confirm the request genuinely came from AXIAM and was not tampered with in transit.",
      },
      { type: "h", id: "verify", text: "Verifying a payload" },
      {
        type: "p",
        text: "Compute the HMAC-SHA256 of the raw request body using your endpoint's shared secret and compare it, in constant time, against the signature header.",
      },
      {
        type: "code",
        caption: "verify a webhook signature (Node)",
        code: "import { createHmac, timingSafeEqual } from 'node:crypto';\n\nfunction verify(rawBody, signature, secret) {\n  const expected = createHmac('sha256', secret)\n    .update(rawBody)\n    .digest('hex');\n  return timingSafeEqual(\n    Buffer.from(expected),\n    Buffer.from(signature),\n  );\n}",
      },
    ],
  },

  {
    slug: "audit",
    section: "Platform",
    navLabel: "Audit logging",
    title: "Audit logging",
    intro:
      "An append-only, tamper-evident record of every privileged action.",
    blocks: [
      { type: "h", id: "appendonly", text: "Append-only by design" },
      {
        type: "p",
        text: "The audit log is append-only: there are no UPDATE or DELETE paths. Records are chained and signed, so any attempt to alter or remove history is detectable after the fact. Audit ingestion runs asynchronously over AMQP to stay off the request hot path.",
      },
      { type: "h", id: "signing", text: "Cryptographic signing" },
      {
        type: "p",
        text: "Entries are signed with GnuPG/OpenPGP keys managed by the PKI layer, giving you an independently verifiable trail. Combined with the chain between records, this makes the log tamper-evident rather than merely tamper-resistant.",
      },
      {
        type: "note",
        text: "Because audit is a first-class subsystem, every authentication, authorization and administrative action across all tenants flows through the same signed, append-only pipeline.",
      },
    ],
  },

  {
    slug: "deploy",
    section: "Operate",
    navLabel: "Docker & Kubernetes",
    title: "Docker & Kubernetes",
    intro:
      "Package AXIAM as a container and run it on Kubernetes with the provided manifests.",
    blocks: [
      { type: "h", id: "docker", text: "Docker" },
      {
        type: "p",
        text: "The `docker/` directory holds the Dockerfiles and compose configuration used for local development and for building the production image. The same image runs the `axiam-server` binary that composes every crate.",
      },
      { type: "h", id: "k8s", text: "Kubernetes" },
      {
        type: "p",
        text: "The `k8s/` directory contains manifests for deploying AXIAM alongside SurrealDB and RabbitMQ. TLS 1.3 is required for all external traffic, so terminate or pass through TLS accordingly at your ingress.",
      },
      {
        type: "code",
        caption: "apply the manifests",
        code: "kubectl apply -k k8s/\nkubectl -n axiam get pods",
      },
      {
        type: "warn",
        text: "AXIAM is an early alpha and should not be used in production until it reaches a stable release. Treat these manifests as a starting point for staging environments.",
      },
    ],
  },

  {
    slug: "configuration",
    section: "Operate",
    navLabel: "Configuration",
    title: "Configuration & environment variables",
    intro:
      "Every setting on the AXIAM server image is an environment variable. This is the reference: what each variable means, its default, and an example value.",
    blocks: [
      { type: "h", id: "naming", text: "The naming convention" },
      {
        type: "p",
        text: "All configuration keys use a double underscore (`__`) after the `AXIAM` prefix — for example `AXIAM__DB__USERNAME`. The `__` separates both the prefix and the nested key levels (this is how the config layer distinguishes them). A single underscore (`AXIAM_DB__USERNAME`) is silently ignored and the in-code default wins, so double-check the doubling when a value doesn't take effect.",
      },
      {
        type: "warn",
        text: "Secrets (database password, JWT keys, the AES-256-GCM encryption keys, the peppers) must come from a secret manager or mounted secret — never bake real key material into an image, a compose file or git. Use a placeholder like `<set-in-secret-manager>` in any template, and never reuse a value across environments.",
      },
      { type: "h", id: "connectivity", text: "Connectivity & bind addresses" },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__DB__URL",
            "SurrealDB address as a bare host:port — not a URL scheme (the Ws engine resolves a scheme as a hostname and fails).",
            "surrealdb:8000",
          ],
          ["AXIAM__DB__NAMESPACE", "SurrealDB namespace.", "axiam"],
          ["AXIAM__DB__DATABASE", "SurrealDB database.", "axiam"],
          [
            "AXIAM__AMQP__URL",
            "RabbitMQ AMQP connection string. Assembled from the broker credentials at the deployment layer.",
            "amqp://user:pass@rabbitmq:5672",
          ],
          [
            "AXIAM__SERVER__HOST",
            "REST bind address (default 127.0.0.1). Set 0.0.0.0 in a container.",
            "0.0.0.0",
          ],
          ["AXIAM__SERVER__PORT", "REST bind port (default 8090).", "8090"],
          [
            "AXIAM__GRPC__HOST",
            "gRPC bind address (default 127.0.0.1, loopback-only). Set 0.0.0.0 to serve in-cluster.",
            "0.0.0.0",
          ],
          ["AXIAM__GRPC__PORT", "gRPC bind port (default 50051).", "50051"],
          [
            "AXIAM__GRPC__GRPC_AUTHZ_PER_SEC",
            "Max gRPC authz requests per second per IP (default 100).",
            "100",
          ],
          [
            "AXIAM__SERVER__CORS_ALLOWED_ORIGINS",
            "Allowed CORS origins; empty disables cross-origin requests (restrictive default).",
            "https://admin.acme.dev",
          ],
          [
            "RUST_LOG",
            "Log verbosity / filter. Keep it narrow in production — no internal module exposure.",
            "info",
          ],
        ],
      },
      { type: "h", id: "secrets", text: "Secrets & encryption keys" },
      {
        type: "p",
        text: "These are required for a real deployment. Generate the 32-byte hex keys with `openssl rand -hex 32` and the Ed25519 JWT keypair with `openssl genpkey -algorithm ed25519`.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          ["AXIAM__DB__USERNAME", "SurrealDB username.", "axiam"],
          ["AXIAM__DB__PASSWORD", "SurrealDB password.", "<set-in-secret-manager>"],
          [
            "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM",
            "Ed25519 JWT signing private key (PEM).",
            "-----BEGIN PRIVATE KEY----- …",
          ],
          [
            "AXIAM__AUTH__JWT_PUBLIC_KEY_PEM",
            "Ed25519 JWT verification public key (PEM), paired with the private key.",
            "-----BEGIN PUBLIC KEY----- …",
          ],
          [
            "AXIAM__AUTH__MFA_ENCRYPTION_KEY",
            "AES-256-GCM key (32-byte hex) encrypting TOTP MFA secrets at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__PKI__ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting CA signing keys (and webhook secrets) at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting SAML/OIDC federation client secrets at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__EMAIL_ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting email/SMTP secrets; also gates the email-config admin endpoints.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__GDPR_PSEUDONYM_PEPPER",
            "HMAC-SHA256 pepper (hex) pseudonymizing audit-log actor identities on GDPR erasure.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__AUTH__PEPPER",
            "Password pepper (string) prepended before Argon2id hashing.",
            "<random string>",
          ],
        ],
      },
      { type: "h", id: "oauth2", text: "OAuth2 & OIDC" },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__OAUTH2_ISSUER_URL",
            "Public issuer URL for OIDC discovery. Must be an origin, not a path (path-based issuers are rejected).",
            "https://iam.acme.dev",
          ],
          [
            "AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS",
            "Cache-Control max-age on the JWKS endpoint, in seconds.",
            "300",
          ],
          [
            "AXIAM__AUTH__ALLOW_MISSING_AUD_AS_USER",
            "Compatibility switch — treat a token with no audience claim as a user token. Leave off unless you need it.",
            "false",
          ],
        ],
      },
      { type: "h", id: "hashing", text: "Argon2id hash concurrency" },
      {
        type: "p",
        text: "Each in-flight Argon2id operation allocates a ~19 MiB arena, so unbounded concurrency is a memory-DoS vector. A process-wide semaphore caps peak concurrent arenas and sheds excess load with a 503 rather than queueing unboundedly. The cost parameters themselves are never weakened for throughput.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__MAX_CONCURRENT_HASHES",
            "Max concurrent Argon2id hash/verify ops. 0 (default) = auto → min(CPU cores, 4). Peak crypto RSS ≈ this × 19 MiB.",
            "0",
          ],
          [
            "AXIAM__AUTH__HASH_ACQUIRE_TIMEOUT_SECS",
            "Seconds a request waits for a hash permit before returning a 503 backpressure error (default 5).",
            "5",
          ],
        ],
      },
      { type: "h", id: "authz-cache", text: "Authorization decision cache (optional)" },
      {
        type: "p",
        text: "An optional per-tenant cache that skips the SurrealDB round-trips per check. Off by default; enabling it changes performance only, never the decision returned. Every access-narrowing mutation invalidates the affected entries immediately, so no revocation can leave a stale allow — the TTL is only a bounded-staleness backstop.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTHZ__DECISION_CACHE_ENABLED",
            "Master switch (default false).",
            "false",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS",
            "Cached-decision TTL, and the upper bound on revocation latency if an invalidation is ever missed (default 5).",
            "5",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES",
            "Max cached decisions per tenant before FIFO eviction (default 10000).",
            "10000",
          ],
        ],
      },
      { type: "h", id: "rate-limit", text: "Rate limiting" },
      {
        type: "p",
        text: "Every auth/OAuth2 endpoint is rate-limited per-key, per-minute. Defaults are shown; `/auth/login` always keys per-IP regardless of the key mode.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          ["AXIAM__RATE_LIMIT__LOGIN_PER_MIN", "Max /auth/login per minute per key.", "10"],
          ["AXIAM__RATE_LIMIT__REGISTER_PER_MIN", "Max register requests per minute.", "5"],
          ["AXIAM__RATE_LIMIT__TOKEN_PER_MIN", "Max /oauth2/token per minute.", "20"],
          [
            "AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN",
            "Max password-reset requests per minute.",
            "3",
          ],
          ["AXIAM__RATE_LIMIT__MFA_PER_MIN", "Max MFA enroll/confirm/verify per minute.", "5"],
          [
            "AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN",
            "Max /oauth2/introspect per minute.",
            "10",
          ],
          ["AXIAM__RATE_LIMIT__REVOKE_PER_MIN", "Max /oauth2/revoke per minute.", "10"],
          [
            "AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN",
            "Max authz-check requests per minute.",
            "300",
          ],
          [
            "AXIAM__RATE_LIMIT__TRUSTED_HOPS",
            "Trusted reverse-proxy hops to skip from the right of X-Forwarded-For (set 1 behind a single ingress).",
            "0",
          ],
          [
            "AXIAM__RATE_LIMIT__KEY",
            "Bucket-key mode for token/introspect/revoke: ip | client_id | ip_client_id.",
            "ip",
          ],
        ],
      },
      { type: "h", id: "tls", text: "Direct TLS termination (opt-in)" },
      {
        type: "p",
        text: "By default the server binds plaintext and a proxy/ingress terminates TLS 1.3 in front of it. To terminate TLS inside the server process instead, set the following — the listener then binds with rustls restricted to TLS 1.3 only. When enabled, both paths are mandatory and the server fails fast at startup on a missing, unreadable or mismatched cert/key (it never falls back to plaintext).",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__SERVER__TLS__ENABLED",
            "Enable in-process TLS 1.3 (default false).",
            "true",
          ],
          [
            "AXIAM__SERVER__TLS__CERT_PATH",
            "Path to the PEM certificate chain (leaf first).",
            "/etc/axiam/tls/tls.crt",
          ],
          [
            "AXIAM__SERVER__TLS__KEY_PATH",
            "Path to the PEM private key (PKCS#8, PKCS#1 or SEC1).",
            "/etc/axiam/tls/tls.key",
          ],
        ],
      },
      {
        type: "note",
        text: "The AMQP URL is assembled from the broker's own `RABBITMQ_DEFAULT_USER` / `RABBITMQ_DEFAULT_PASS` into `AXIAM__AMQP__URL` at the deployment layer. See Docker & Kubernetes for how the shipped compose file and manifests wire these together.",
      },
    ],
  },

  {
    slug: "sdks",
    section: "Operate",
    navLabel: "SDKs",
    title: "Client SDKs",
    intro:
      "Eleven official client libraries, all conforming to one cross-language behavioral contract.",
    blocks: [
      { type: "h", id: "contract", text: "One contract, many languages" },
      {
        type: "p",
        text: "AXIAM ships SDKs for Rust, TypeScript, Python, Java, C#, PHP, Go, Kotlin, Swift, C and C++. Each lives in its own repository but vendors the same CONTRACT.md, OpenAPI spec and protobuf definitions, so behavior is identical whichever language you pick. The contract spans login and MFA, authorization, secret handling, strict TLS/mTLS, single-flight refresh and declarative route guards.",
      },
      {
        type: "p",
        text: "The original seven — Rust, TypeScript, Python, Java, C#, PHP and Go — implement the full §1–§11 contract including the gRPC and AMQP transports. The Kotlin, Swift, C and C++ SDKs cover the REST surface (§1–§7, §9–§11, including §6.1 mTLS); gRPC and AMQP are planned follow-ups for them.",
      },
      {
        type: "p",
        text: "Tenant is always an explicit constructor parameter — AXIAM is multi-tenant, and there is no default tenant.",
      },
      { type: "h", id: "pick", text: "Pick your language" },
      {
        type: "cards",
        cards: [
          {
            title: "All SDKs →",
            body: "Install snippets and quickstarts for every language.",
            to: "sdks",
          },
          {
            title: "Back to Quickstart →",
            body: "Run the stack and make your first check.",
            to: "docs",
          },
        ],
      },
    ],
  },
];
