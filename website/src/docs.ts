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
    slugs: ["auth", "authz", "oauth2", "federation", "pki", "webhooks", "audit"],
  },
  { label: "Operate", slugs: ["deploy", "sdks"] },
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
        code: "import { AxiamClient } from 'axiam-sdk';\n\nconst axiam = new AxiamClient({\n  baseUrl: 'https://iam.acme.dev',\n  tenantSlug: 'acme',\n});\n\nawait axiam.login(email, password);\nconst ok = await axiam.can('read', 'doc:1');",
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
            body: "Quickstarts for all seven languages.",
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
    slug: "sdks",
    section: "Operate",
    navLabel: "SDKs",
    title: "Client SDKs",
    intro:
      "Seven official client libraries, all conforming to one cross-language behavioral contract.",
    blocks: [
      { type: "h", id: "contract", text: "One contract, seven languages" },
      {
        type: "p",
        text: "AXIAM ships SDKs for Rust, TypeScript, Python, Java, C#, PHP and Go. Each lives in its own repository but vendors the same CONTRACT.md, OpenAPI spec and protobuf definitions, so behavior is identical whichever language you pick. The contract spans login and MFA, REST/gRPC/AMQP authorization, secret handling, strict TLS, single-flight refresh and declarative route guards.",
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
