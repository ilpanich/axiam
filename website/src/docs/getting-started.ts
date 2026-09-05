import type { DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

/**
 * "Getting started" — the path from nothing to a running instance with a real
 * tenant and a first authorization decision.
 *
 * The ordering is deliberate and is the one thing to preserve when editing:
 * overview (what this is) → quickstart (see it work) → installation (build it
 * properly) → bootstrap (make it yours) → concepts (understand what you just
 * did). A reader who stops after any one page has something that works.
 */
export const GETTING_STARTED_PAGES: DocPage[] = [
  {
    slug: "overview",
    section: "Getting started",
    navLabel: "What is AXIAM?",
    title: "What is AXIAM?",
    intro:
      "A multi-tenant identity and access management server written in Rust — OAuth2 and OpenID Connect provider, RBAC authorization engine, PKI, and an audit trail, reachable over REST, gRPC and AMQP.",
    blocks: [
      { type: "h", id: "what", text: "In one paragraph" },
      {
        type: "p",
        text: "AXIAM issues and validates identities, and answers the question *may this principal perform this action on this resource?* It is a complete OAuth2 authorization server and OpenID Connect provider, a role-based authorization engine that evaluates over a hierarchy of resources, a certificate authority for machine identities, and an append-only audit log — all of it partitioned by tenant, so one deployment can serve many isolated customers without any of them being able to observe another.",
      },
      {
        type: "p",
        text: "It is built for the two workloads that stress an IAM system in different directions: **microservices**, where an authorization check happens on nearly every request and tail latency is the constraint, and **IoT fleets**, where identities are certificates rather than passwords and devices commission themselves without a browser.",
      },
      { type: "h", id: "capabilities", text: "What it does" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Area", "Capability"],
        rows: [
          [
            "Authentication",
            "Password (Argon2id), OPAQUE (RFC 9807, password never leaves the client), TOTP, WebAuthn passkeys and security keys, X.509 client certificates, and federated sign-in via SAML or OIDC.",
          ],
          [
            "Authorization",
            "Role-based, default-deny, with deny-override precedence, a cascading resource hierarchy, sub-resource scopes, groups, service accounts, and UMA 2.0 for resource servers that guard what they do not own.",
          ],
          [
            "Standards",
            "OAuth2 (authorization code + PKCE, client credentials, refresh, device grant, token exchange, PAR), OpenID Connect with discovery and RP-initiated plus back-channel logout, FAPI 2.0 Security Profile, SCIM 2.0 provisioning.",
          ],
          [
            "Machine identity",
            "Per-tenant X.509 issuance under an organization CA, mTLS authentication terminated in-process, certificate-bound access tokens, and OpenPGP keys for audit signing and encrypted exports.",
          ],
          [
            "Operations",
            "Append-only signed audit log, webhooks, Reactors (external hook actors on the AMQP bus), pluggable secret providers including HashiCorp Vault, and GDPR export/erasure endpoints.",
          ],
        ],
      },
      { type: "h", id: "protocols", text: "Three protocols, one engine" },
      {
        type: "p",
        text: "The same domain logic is reachable three ways. Choosing between them is a transport decision, not a capability one — an authorization check returns the same answer whichever door it arrives through.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Protocol", "Use it for", "Spec"],
        rows: [
          [
            "REST",
            "Administration, the admin console, and any HTTP integrator. The broadest surface — every entity is manageable here.",
            "OpenAPI 3.1 (`sdks/openapi.json`)",
          ],
          [
            "gRPC",
            "The hot path inside a service mesh: authorization checks, token validation and user lookups where connection reuse and binary framing matter.",
            "Protocol Buffers (`proto/axiam/v1/`)",
          ],
          [
            "AMQP",
            "Deferred authorization decisions, audit ingestion, mail, webhook and notification delivery, and Reactor hooks.",
            "AsyncAPI 2.6 (`docs/api/asyncapi.yml`)",
          ],
        ],
      },
      { type: "h", id: "shape", text: "How a deployment is shaped" },
      {
        type: "code",
        caption: "the runtime picture",
        code: "  Browsers · Mobile · IoT devices · Services · Admin console\n        |             |              |\n     REST/HTTPS    gRPC/mTLS       AMQP\n        |             |              |\n        v             v              v\n  +-------------------------------------------+\n  |               axiam-server                |\n  |   Actix-Web  |  Tonic  |  Lapin consumer  |\n  +-------------------------------------------+\n  |  AuthN · AuthZ · OAuth2/OIDC · Federation |\n  |  PKI · SCIM · Audit · Email · Reactors    |\n  +-------------------------------------------+\n        |                        |\n        v                        v\n   SurrealDB                RabbitMQ\n  (all domain state)   (async work + events)\n        |\n        v\n   HashiCorp Vault  (long-lived secrets, production)",
      },
      {
        type: "p",
        text: "`axiam-server` is a single binary composing a workspace of focused crates. It is stateless: every piece of durable state lives in SurrealDB, so replicas scale horizontally behind an ordinary load balancer.",
      },
      { type: "h", id: "status", text: "Project status" },
      {
        type: "warn",
        text: "AXIAM is pre-1.0 and under active development. It should not carry production identity traffic until it reaches a stable release. The security posture described throughout these docs is a self-assessment backed by tests and a threat model — not a certified third-party audit.",
      },
      { type: "h", id: "start", text: "Where to go next" },
      {
        type: "cards",
        cards: [
          {
            title: "Quickstart →",
            body: "Run the stack and make your first authorization check.",
            to: "docs",
            doc: "quickstart",
          },
          {
            title: "Browse the SDKs →",
            body: "Install snippets and quickstarts for eleven languages.",
            to: "sdks",
          },
          {
            title: "See the benchmarks →",
            body: "Measured throughput, latency and the cost of each security tier.",
            to: "bench",
          },
          {
            title: "Read the security model →",
            body: "Threat model, cryptography choices and shared responsibility.",
            to: "security",
          },
        ],
      },
    ],
  },

  {
    slug: "quickstart",
    section: "Getting started",
    navLabel: "Quickstart",
    title: "Quickstart",
    intro:
      "Get a local AXIAM instance running, create your first admin, then make an authenticated authorization check — in about ten minutes.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "prereq", text: "Prerequisites" },
      {
        type: "p",
        text: "AXIAM builds with Rust 1.93+ and runs its dev infrastructure (SurrealDB + RabbitMQ) in Docker. The `just` task runner wraps the common commands. If you only want to *use* a running instance, you need none of this — skip to [your first check](#authz) and point an SDK at your server.",
      },
      { type: "h", id: "run", text: "1. Start the stack" },
      {
        type: "code",
        caption: "terminal",
        code: "# clone and enter the repository\ngit clone https://github.com/ilpanich/axiam.git\ncd axiam\n\n# start dev infrastructure (SurrealDB + RabbitMQ)\njust dev-up\n\n# build and run the server\njust build\njust run",
      },
      {
        type: "p",
        text: "The REST API comes up on `http://localhost:8090` and gRPC on `localhost:50051`. Confirm it is alive and that it can reach the database:",
      },
      {
        type: "code",
        code: "curl -s localhost:8090/health   # liveness  — always 200 if the process is up\ncurl -s localhost:8090/ready    # readiness — 200 only when SurrealDB answers",
      },
      { type: "h", id: "admin", text: "2. Create the first admin" },
      {
        type: "p",
        text: "A fresh deployment has no users at all, and the bootstrap endpoint that creates the first one is fail-closed — it refuses unless you prove you are the operator. It creates an organization and an organization-level super-admin, and no ordinary tenant: create the tenant you will work in from the signed-in session, with `POST /api/v1/organizations/{org_id}/tenants`. The full procedure, both gates and the seeded role set are on [First organization and admin](#/docs/bootstrap).",
      },
      {
        type: "code",
        caption: "the short version",
        code: "# Lock bootstrap to a known address before starting the server\nexport AXIAM_BOOTSTRAP_ADMIN_EMAIL=admin@acme.dev\n\ncurl -X POST localhost:8090/api/v1/admin/bootstrap \\\n  -H 'content-type: application/json' \\\n  -d '{\n        \"organization_name\": \"Acme\",\n        \"organization_slug\": \"acme\",\n        \"email\": \"admin@acme.dev\",\n        \"username\": \"admin\",\n        \"password\": \"'\"$ADMIN_PASSWORD\"'\"\n      }'",
      },
      { type: "h", id: "authz", text: "3. Your first authorization check" },
      {
        type: "p",
        text: "Install a client SDK, construct a client for your tenant, sign in, then call `can()`. Tenant is always explicit — AXIAM is multi-tenant and has no default tenant, so there is no ambient context to get wrong.",
      },
      {
        type: "codegroup",
        caption: "authenticate, then check",
        tabs: [
          {
            label: "TypeScript",
            code: "import { AxiamClient } from 'axiam-sdk';\n\nconst client = new AxiamClient({\n  baseUrl: 'https://iam.acme.dev',\n  tenantSlug: 'acme',\n  orgSlug: 'acme',\n});\n\nconst result = await client.login(email, password);\nif (result.status === 'mfa_required') {\n  await client.verifyMfa(result.mfaToken, code);\n}\n\nconst allowed = await client.can('read', 'doc:1');",
          },
          {
            label: "Python",
            code: "from axiam_sdk import AxiamClient\n\nwith AxiamClient(\n    base_url=\"https://iam.acme.dev\",\n    tenant_slug=\"acme\",\n    org_slug=\"acme\",\n) as client:\n    result = client.login(email, password)\n    if result.mfa_required:\n        result = client.verify_mfa(result.mfa_token, totp_code)\n\n    allowed = client.can(\"read\", resource_id)",
          },
          {
            label: "Rust",
            code: "use axiam_sdk::AxiamClient;\n\nlet client = AxiamClient::builder()\n    .base_url(\"https://iam.acme.dev\")?\n    .tenant_slug(\"acme\")\n    .org_slug(\"acme\")\n    .build()?;\n\nlet result = client.login(\"user@acme.dev\", &password).await?;\nif result.mfa_required {\n    client.verify_mfa(\"123456\").await?;\n}\n\nlet allowed = client.can(\"read\", resource_id, None).await?;",
          },
          {
            label: "Go",
            code: "import axiam \"github.com/ilpanich/axiam-go-sdk\"\n\n// tenantSlug is required — there is no default tenant. Login also needs\n// organization context: a tenant slug is only unique within an org.\nclient, err := axiam.NewClient(baseURL, \"acme\", axiam.WithOrgSlug(\"acme\"))\n\nresult, err := client.Login(ctx, email, password)\nif result.MFARequired {\n    // complete the challenge\n}\n\nallowed, err := client.Can(ctx, \"read\", resourceID)",
          },
          {
            label: "Java",
            code: "try (AxiamClient client = AxiamClient.builder(\"https://iam.acme.dev\", \"acme\")\n        .orgSlug(\"acme\")\n        .build()) {\n    LoginResult result = client.login(\"user@acme.dev\", password);\n    if (result.mfaRequired()) {\n        result = client.verifyMfa(result.challengeToken(), \"123456\");\n    }\n\n    boolean allowed = client.can(\"read\", \"doc:1\");\n}",
          },
        ],
      },
      {
        type: "note",
        text: "In a browser, tokens arrive only via `httpOnly` cookies — CSRF forwarding and single-flight refresh are handled for you, and browser code imports only from `axiam-sdk/rest`. There is no code path in any SDK that puts a token in `localStorage`.",
      },
      { type: "h", id: "curl", text: "The same thing over plain HTTP" },
      {
        type: "p",
        text: "No SDK required — every capability is reachable with an HTTP client. Two things to know before you start: **login returns no token in its body**. It sets three cookies — `axiam_access`, `axiam_refresh` and a non-`httpOnly` `axiam_csrf` — so a raw HTTP client needs a cookie jar. And every state-changing request must echo the CSRF cookie back in an `X-CSRF-Token` header; `/auth/login`, the OPAQUE start endpoints and everything under `/oauth2/` are exempt, because their callers have no CSRF cookie yet.",
      },
      {
        type: "code",
        caption: "login, then check — with a cookie jar",
        code: "# 1. authenticate. The tokens come back as cookies, not in the body.\ncurl -sS -c jar.txt -X POST https://iam.acme.dev/api/v1/auth/login \\\n  -H 'content-type: application/json' \\\n  -d '{\"org_slug\":\"acme\",\"tenant_slug\":\"production\",\n       \"username_or_email\":\"admin@acme.dev\",\"password\":\"...\"}'\n\n# 2. state-changing calls echo the CSRF cookie in a header.\nCSRF=$(awk '/axiam_csrf/ {print $7}' jar.txt)\n\ncurl -sS -b jar.txt -X POST https://iam.acme.dev/api/v1/authz/check \\\n  -H \"x-csrf-token: $CSRF\" \\\n  -H 'content-type: application/json' \\\n  -d '{\"action\":\"read\",\"resource_id\":\"doc:1\"}'",
      },
      {
        type: "note",
        text: "A **machine** client does not do any of this. It uses the OAuth2 client-credentials grant, which *does* return `access_token` in the response body, and then sends `Authorization: Bearer <token>` — no cookie jar and no CSRF header. See [Service accounts](#/docs/service-accounts).",
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
      {
        type: "cards",
        cards: [
          {
            title: "Work through the tutorial →",
            body: "The same ground at walking pace: a tenant, a role model, a working authorization check.",
            to: "docs",
            doc: "tutorial",
          },
          {
            title: "Other ways to install →",
            body: "Docker, Kubernetes, or building from source — and what each one expects of you.",
            to: "docs",
            doc: "installation",
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
      "Build AXIAM from source, or run the whole stack in containers. Both paths, and what each one is good for.",
    blocks: [
      { type: "h", id: "which", text: "Which path?" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["You want to…", "Use", "Notes"],
        rows: [
          [
            "Develop against AXIAM, or on it",
            "`just dev-up` + a natively-run server",
            "Only SurrealDB and RabbitMQ run in Docker; the server runs on your machine so you get fast rebuilds and a debugger.",
          ],
          [
            "Validate the whole stack end to end",
            "`just prod-up`",
            "Server, admin console, database and broker in Compose. Documented as *not* for real production — it exists to prove the pieces fit.",
          ],
          [
            "Run it for real",
            "The Kubernetes manifests in `k8s/`",
            "See [Docker & Kubernetes](#/docs/deploy) and [Production hardening](#/docs/hardening).",
          ],
        ],
      },
      { type: "h", id: "toolchain", text: "Toolchain" },
      {
        type: "p",
        text: "AXIAM is a Cargo workspace of focused crates — `axiam-core` holds the domain types, `axiam-db` the SurrealDB repositories, `axiam-auth`, `axiam-authz`, `axiam-oauth2`, `axiam-pki`, `axiam-scim` and the rest hold one concern each, and `axiam-server` composes them into the runnable binary. You need a Rust 1.93+ toolchain, Docker, and the `just` task runner.",
      },
      {
        type: "code",
        caption: "install the task runner",
        code: "# macOS\nbrew install just\n\n# or via cargo, anywhere\ncargo install just",
      },
      { type: "h", id: "services", text: "Backing services" },
      {
        type: "p",
        text: "`just dev-up` starts the development infrastructure in Docker: a SurrealDB node (the document/graph store behind every domain entity) and a RabbitMQ broker (async authorization, audit ingestion, mail and event delivery). `just dev-down` stops them again.",
      },
      {
        type: "code",
        code: "just dev-up      # start SurrealDB + RabbitMQ\njust dev-down    # stop them",
      },
      { type: "h", id: "build", text: "Build & verify" },
      {
        type: "code",
        code: "just build       # compile the workspace\njust test        # run all tests\njust check       # fmt + lint + test — the same gate CI enforces",
      },
      { type: "h", id: "features", text: "Optional build features" },
      {
        type: "p",
        text: "SAML federation is behind a default-on `saml` feature because it links `libxml`, which needs system libxml2 headers. Where those are unavailable, build without default features — this is exactly what CI's *Build (SAML off)* job does, and everything except the SAML service-provider path is unaffected.",
      },
      {
        type: "code",
        code: "cargo build -p axiam-server --no-default-features",
      },
      { type: "h", id: "compose", text: "The full stack in Compose" },
      {
        type: "p",
        text: "`just prod-up` builds and starts `axiam-server`, the admin console, SurrealDB and RabbitMQ together. It generates a local-only Ed25519 signing keypair under `docker/.secrets/` on first run and refuses to start if the database and broker credentials are not set in your shell — the Compose file uses fail-fast variable syntax rather than silently defaulting.",
      },
      {
        type: "code",
        code: "just prod-up      # build + start everything\n#   admin console  http://localhost:8081\n#   REST API       http://localhost:8090\n#   gRPC           localhost:50051\n\njust prod-down    # stop, keep volumes\njust prod-clean   # stop and remove volumes",
      },
      {
        type: "warn",
        text: "`docker-compose.prod.yml` is a workstation validation tool, not a production deployment. It is named for the production *image* it builds, not for where it should run. Use the Kubernetes manifests for anything real.",
      },
    ],
  },

  {
    slug: "bootstrap",
    section: "Getting started",
    navLabel: "First organization & admin",
    title: "The bootstrap procedure",
    intro:
      "A fresh AXIAM has no organizations and no users — and every administrative endpoint requires an authenticated caller who holds an explicit grant. Bootstrap is the one call that resolves that circularity, and it is built so that it can only ever be made by the operator, exactly once. It creates an organization and an organization-level super-admin; the tenants you actually work in come afterwards, from a signed-in session.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "why", text: "The problem bootstrap solves" },
      {
        type: "p",
        text: "AXIAM is default-deny all the way down: a caller needs a token, and the principal behind that token needs a permission grant, for every administrative action. On a brand-new deployment nobody satisfies either condition, so something has to create the first administrator out of nothing. That something is `POST /api/v1/admin/bootstrap` — the only privileged endpoint reachable without an access token.",
      },
      {
        type: "p",
        text: "An endpoint like that is worth exactly as much as the gate in front of it, and as much as its guarantee that it cannot run twice. Both are enforced in the database rather than by a check in the handler, which is the part worth understanding before you run it.",
      },
      { type: "h", id: "does", text: "What one call does" },
      {
        type: "p",
        text: "Bootstrap is a single call that provisions the entire first-run state, inside one transaction. There is no partially-bootstrapped outcome: either all of the following exists afterwards, or none of it does.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Creates the organization",
            body: "From `organization_name`, with `organization_slug` derived from it when you do not supply one. Get-or-create by slug, so retrying after a transient failure reuses the organization rather than duplicating it.",
          },
          {
            title: "Creates the organization's reserved scope",
            body: "Not an ordinary tenant — the organization's own scope, slugged `organization`, which is where the super-admin will live. Get-or-create, so a concurrent racer reads the winner's row rather than duplicating it. **No ordinary tenant is created at all**; you create those once you are signed in.",
          },
          {
            title: "Seeds the permission registry into that scope",
            body: "All 115 built-in permissions across 25 families — `users:*`, `roles:*`, `resources:*`, `oauth2_clients:*`, `certificates:*`, `audit_logs:*`, `reactors:*`, `gdpr:*` and the rest. These are the actions the REST API's own route guards check against.",
          },
          {
            title: "Seeds three default roles",
            body: "`super-admin` (full system access — every permission), `admin` (all entity CRUD) and `viewer` (read-only: list and get). Seeding is idempotent — already-granted pairs are skipped rather than re-granted.",
          },
          {
            title: "Creates the admin user and binds the super-admin role",
            body: "The password is hashed with Argon2id server-side. If you asked for an OPAQUE baseline, the registration record is created here too. The account lives in the organization scope, which is what makes it an administrator of every tenant the organization ever has — including ones created long afterwards.",
          },
          {
            title: "Takes the bootstrap lock",
            body: "A uniqueness-invariant `bootstrap_lock:global` row is created in the same transaction. This is what makes the operation one-shot — see below.",
          },
        ],
      },
      {
        type: "note",
        text: "Bootstrap issues **no token**. The new admin authenticates through `POST /api/v1/auth/login` like anybody else. That is deliberate: a provisioning endpoint that also hands out a session is a provisioning endpoint that is worth attacking twice.",
      },
      {
        type: "warn",
        text: "**Bootstrap no longer creates an ordinary tenant.** It used to, and that is precisely what left every *later* tenant unreachable by everybody: the super-admin's grants were rows in the one tenant bootstrap happened to create, and the authorization engine filters every lookup by tenant. The super-admin is now organization-level and reaches new tenants by rule rather than by a grant somebody has to remember to write. `tenant_name` and `tenant_slug` are still **accepted and ignored**, so an older client's request succeeds rather than failing on an unknown field — but nothing reads them, and the `tenant_slug` in the response is the organization scope's own. See [Organization-level principals](#/docs/organization-scope).",
      },
      { type: "h", id: "gates", text: "The gate — fail-closed, two ways to satisfy it" },
      {
        type: "p",
        text: "A request is refused with `403` unless **one** of two gates is satisfied. Neither gate being configured does not mean *allow*; it means the endpoint is unusable until an operator configures one. There is no deployment in which an arbitrary caller can create the first admin.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Gate", "How it works", "When to prefer it"],
        rows: [
          [
            "`AXIAM_BOOTSTRAP_ADMIN_EMAIL`",
            "Set this environment variable on the `axiam-server` process before it starts. The request's `email` field must match it **exactly**, or the call is refused. When this variable is set to a non-empty value, `setup_token` is ignored entirely.",
            "Automated and declarative deployments. The operator names the first admin before the server exists, and nothing has to be recovered from a log.",
          ],
          [
            "One-time setup token",
            "Used only when the variable is unset. On first boot — and only while no admin has ever been bootstrapped — the server mints a random token, stores its SHA-256 hash, and logs the token once at `info`. Pass it as `setup_token`.",
            "Interactive installs and local exploration, where you are watching the server start.",
          ],
        ],
      },
      {
        type: "p",
        text: "The token is single-use, and that is enforced twice. A pre-check rejects a hash that is unknown or already consumed; the authoritative guarantee is a `bootstrap_setup_token_consumed` row created inside the same transaction as the admin user, so two requests racing past the pre-check still leave exactly one winner — the loser hits a uniqueness violation and its whole transaction rolls back.",
      },
      {
        type: "warn",
        text: "The setup token is written to the server log exactly once, at `info` level. If your log pipeline drops `info`, buffers it, or you simply scroll past it, there is no way to re-read or re-mint it. Set `AXIAM_BOOTSTRAP_ADMIN_EMAIL` and restart instead — for anything unattended, prefer that gate in the first place.",
      },
      {
        type: "note",
        text: "**An empty value is not a gate.** `AXIAM_BOOTSTRAP_ADMIN_EMAIL` set to the empty string — the shape Docker Compose produces for `AXIAM_BOOTSTRAP_ADMIN_EMAIL: \"${AXIAM_BOOTSTRAP_ADMIN_EMAIL:-}\"` when nothing is exported — is treated as unset, and the call falls through to the setup-token path. It used to be read as \"gate configured\", compared the request email against nothing, answered 403 and made the token path unreachable, so a deployment holding a perfectly valid one-time token could not bootstrap at all.",
      },
      {
        type: "note",
        text: "`AXIAM_BOOTSTRAP_ADMIN_EMAIL` uses a **single** underscore after the prefix, unlike the `AXIAM__*` configuration variables. It is read straight from the environment rather than through the layered config loader, which is why it does not follow that convention — and why doubling the underscore here silently disables the gate.",
      },
      { type: "h", id: "once", text: "Why it can only ever run once" },
      {
        type: "p",
        text: "The one-shot property is not a `SELECT` followed by an `INSERT` — that pattern has a window between the two in which a second caller can also pass. Instead, creating the first super-admin includes creating `bootstrap_lock:global`, a row whose record id is a uniqueness invariant, in the *same* transaction.",
      },
      {
        type: "list",
        items: [
          "**Two concurrent first-run requests** — both attempt the lock, one wins, the loser gets `409 Conflict` and rolls back completely. At most one super-admin can exist, with no orphaned role assignment left behind.",
          "**Any later call** — hits the same uniqueness violation and is refused with `409`. Additional organizations, tenants and admins are created through the authenticated admin API from then on.",
        ],
      },
      { type: "h", id: "request", text: "Request fields" },
      {
        type: "table",
        headers: ["Field", "Required", "Meaning"],
        rows: [
          ["organization_name", "yes", "Display name of the organization to create."],
          [
            "organization_slug",
            "no",
            "URL-safe slug. Derived from `organization_name` when omitted or blank — ASCII alphanumerics are lower-cased and every other run of characters collapses to a single dash.",
          ],
          [
            "tenant_name",
            "no",
            "**Deprecated and ignored.** Accepted so an older client's request still succeeds. Bootstrap creates no ordinary tenant; use `POST /api/v1/organizations/{org_id}/tenants` once signed in.",
          ],
          ["tenant_slug", "no", "**Deprecated and ignored.** See `tenant_name`."],
          ["email", "yes", "Admin email address. Must match `AXIAM_BOOTSTRAP_ADMIN_EMAIL` when that gate is in use."],
          ["username", "yes", "Admin username."],
          ["password", "yes", "Admin password. Hashed with Argon2id before storage."],
          [
            "setup_token",
            "conditional",
            "Required when `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is not set; ignored when it is.",
          ],
          [
            "opaque_mode",
            "no",
            "Seeds the new organization's OPAQUE baseline: `disabled` (the default), `optional` or `required`.",
          ],
          [
            "opaque_suite",
            "no",
            "RFC 9807 ciphersuite for that baseline. Defaults to `ristretto255_sha512`.",
          ],
          [
            "opaque_ksf",
            "no",
            "Client key-stretching function for that baseline. Defaults to `argon2id`.",
          ],
        ],
      },
      { type: "h", id: "call", text: "Making the call" },
      {
        type: "code",
        caption: "gate 1 — AXIAM_BOOTSTRAP_ADMIN_EMAIL",
        code: "# Set on the axiam-server process, BEFORE it starts.\nexport AXIAM_BOOTSTRAP_ADMIN_EMAIL=admin@acme.dev\n\ncurl -X POST https://iam.acme.dev/api/v1/admin/bootstrap \\\n  -H 'content-type: application/json' \\\n  -d '{\n        \"organization_name\": \"Acme Corporation\",\n        \"organization_slug\": \"acme\",\n        \"email\": \"admin@acme.dev\",\n        \"username\": \"admin\",\n        \"password\": \"'\"$ADMIN_PASSWORD\"'\"\n      }'",
      },
      {
        type: "code",
        caption: "gate 2 — the one-time setup token",
        code: "# Capture the token the server logged once at first boot:\n#   AXIAM first-run bootstrap setup token minted. Use this token ONCE ...\nexport SETUP_TOKEN=...\n\ncurl -X POST https://iam.acme.dev/api/v1/admin/bootstrap \\\n  -H 'content-type: application/json' \\\n  -d '{\n        \"organization_name\": \"Acme Corporation\",\n        \"email\": \"admin@acme.dev\",\n        \"username\": \"admin\",\n        \"password\": \"'\"$ADMIN_PASSWORD\"'\",\n        \"setup_token\": \"'\"$SETUP_TOKEN\"'\"\n      }'",
      },
      {
        type: "code",
        caption: "201 Created",
        code: "{\n  \"message\": \"Bootstrap completed\",\n  \"organization_id\": \"0f8c...\",\n  \"organization_slug\": \"acme\",\n  \"tenant_id\": \"3a91...\",\n  \"tenant_slug\": \"organization\",\n  \"user_id\": \"c47b...\"\n}",
      },
      {
        type: "p",
        text: "The `tenant_id` and `tenant_slug` here are the organization scope's own, reported so you know where the administrator you just created lives — not an ordinary tenant to start putting things in. Keep `organization_slug`: every SDK constructor takes it, and an organization-level principal signs in with the tenant left blank.",
      },
      { type: "h", id: "responses", text: "Response codes" },
      {
        type: "table",
        headers: ["Status", "Meaning", "What to do"],
        rows: [
          ["201", "Organization, tenant and admin created.", "Log in and continue with the checklist below."],
          [
            "400",
            "A required field is missing or blank (`organization_name`, `email`, `username`, `password`).",
            "Fix the body. Nothing was created.",
          ],
          [
            "403",
            "The gate was not satisfied — email mismatch, or a missing/unknown/already-consumed setup token. The error names which.",
            "Check that `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set on the *server* process and matches byte-for-byte, or that you are using a fresh token.",
          ],
          [
            "409",
            "Bootstrap has already completed on this deployment, or a concurrent request won the race.",
            "Not an error to retry. Log in as the existing admin; create further tenants and admins through the authenticated API.",
          ],
        ],
      },
      {
        type: "note",
        text: "On an already-bootstrapped deployment, **which** of those two you get depends on the gate, and deliberately so. The gate is evaluated first: a second call carrying a consumed setup token is refused `403` for the token, never reaching the already-initialised check — so an unauthenticated caller cannot use bootstrap to learn whether a deployment has been initialised. With `AXIAM_BOOTSTRAP_ADMIN_EMAIL` configured, the gate passes and the `409` is what you see.",
      },
      { type: "h", id: "opaque", text: "Seeding an OPAQUE baseline at bootstrap" },
      {
        type: "p",
        text: "`opaque_mode` is settable here, and not only through the settings API afterwards, for one specific reason: OPAQUE's `required` mode cannot be turned on retroactively. A registration record has to be built from the plaintext password, and a stored Argon2id hash is not invertible — so nobody can be enrolled after the fact. If you switched a deployment to `required` while its only account had no record, you would lock the sole administrator out of their own system with no second admin to undo it.",
      },
      {
        type: "p",
        text: "Bootstrap is also the one enrolment path that does not take a client-built record, and that is not a weakening. Every other path requires the client to build the record because the server must never see the plaintext; bootstrap takes `password` in the request body by construction, so it runs the client half of the registration itself. The resulting record is indistinguishable from a client-built one.",
      },
      {
        type: "note",
        text: "If you want an OPAQUE record the server provably never held material for, change the admin password once after bootstrap through the ordinary password-change flow — that path is client-built like every other one.",
      },
      { type: "h", id: "after", text: "What to do immediately after" },
      {
        type: "steps",
        steps: [
          {
            title: "Enrol a second factor on the admin account",
            body: "A single-factor super-admin is the most valuable credential in the deployment. Register a passkey or a TOTP authenticator before anything else.",
          },
          {
            title: "Create a second administrator",
            body: "One admin account is one lost device away from an unrecoverable deployment, and bootstrap cannot be run again to rescue you.",
            code: "POST /api/v1/users            # create the user\nPOST /api/v1/roles/{role_id}/users   # bind them to super-admin",
          },
          {
            title: "Create the tenants you actually need",
            body: "There is no starter tenant to grow out of — bootstrap creates none. Tenants are the isolation boundary: one per customer, environment or business unit. Creating one seeds its permissions and its three default roles, and your organization-level super-admin already reaches it.",
            code: "POST /api/v1/organizations/{org_id}/tenants\n{ \"name\": \"Acme Staging\", \"slug\": \"acme-staging\" }",
          },
          {
            title: "Review the settings baseline",
            body: "Password policy, lockout, token lifetimes, MFA enforcement and the OPAQUE mode all default at the organization and are tightened per tenant.",
            code: "GET /api/v1/organizations/{org_id}/settings",
          },
          {
            title: "Unset the bootstrap gate",
            body: "Once bootstrap has completed, `AXIAM_BOOTSTRAP_ADMIN_EMAIL` does nothing — the lock refuses every further call regardless. Removing it keeps your deployment manifest honest about what is still load-bearing.",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Settings & policies →",
            body: "The org baseline, tenant tighten-only overrides, and every policy field.",
            to: "docs",
            doc: "settings",
          },
          {
            title: "Production hardening →",
            body: "The checklist to work through before this deployment carries real traffic.",
            to: "docs",
            doc: "hardening",
          },
        ],
      },
    ],
  },

  {
    slug: "concepts",
    section: "Getting started",
    navLabel: "Core concepts",
    title: "Core concepts",
    intro:
      "The domain model AXIAM is built around — organizations and tenants at the top, and the entities scoped inside them.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "tenancy", text: "Organizations & tenants" },
      {
        type: "p",
        text: "**Organizations** are the top-level entity. They own the CA certificates, hold the settings baseline, and contain one or more tenants. **Tenants** are the isolation boundary: each has its own users, groups, roles, permissions, resources, certificates, OAuth2 clients, federation configuration and OPAQUE key material. Nothing crosses a tenant boundary implicitly.",
      },
      {
        type: "p",
        text: "There is no default tenant and no ambient tenant context. Every SDK constructor takes one — left blank it means the organization scope, not \"whichever tenant is handy\" — every gRPC request message carries `tenant_id`, and every OAuth2 endpoint takes it as a query parameter. This is deliberate: the most common multi-tenancy bug is a query that forgot to filter, and an API that cannot express *unscoped* cannot express that bug.",
      },
      {
        type: "p",
        text: "One tenant per organization is **reserved**: the organization's own scope, slugged `organization` and flagged `kind: \"organization\"`. It is an ordinary tenant row in every other respect — deliberately, so every isolation control that protects a tenant protects it too — and it is where organization-level principals live. A *global* grant held there applies in every tenant of the organization, including tenants created long afterwards; a resource-scoped one does not travel, because the resource it names exists only in that scope. That is the whole of the cross-tenant rule, and [Organization-level principals](#/docs/organization-scope) is the page for it.",
      },
      {
        type: "code",
        caption: "the containment hierarchy",
        code: "Organization  (CA certificates, settings baseline)\n ├── Organization scope  (reserved; slug `organization`) — estate-wide principals\n └── Tenant   (the isolation boundary)\n      ├── Users, Groups, Service accounts\n      ├── Roles → Permissions (action + resource, allow or deny)\n      ├── Resources (a tree) → Scopes\n      ├── OAuth2 clients, Federation configs\n      ├── Certificates, PGP keys\n      └── Webhooks, Reactors, Notification rules",
      },
      { type: "h", id: "identity", text: "Identities" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Entity", "What it is"],
        rows: [
          [
            "User",
            "A human identity. Authenticates with a password, an OPAQUE record, a federated IdP, a passkey, or a client certificate — with optional MFA on top.",
          ],
          [
            "Group",
            "A named collection of users. Roles assigned to a group are inherited by every member, which is how you avoid per-user grants.",
          ],
          [
            "Service account",
            "A non-human identity for machine-to-machine access. Authenticates with client credentials or a bound X.509 certificate, and can have its secret rotated in place.",
          ],
          [
            "OAuth2 client",
            "A registered application. Confidential or public, with its own redirect URIs, grant types, scopes and — optionally — a FAPI 2.0 constraint bundle.",
          ],
        ],
      },
      { type: "h", id: "access", text: "Roles, permissions & resources" },
      {
        type: "p",
        text: "A **permission** is an action on a resource, carrying an effect of either allow or deny. A **role** is a collection of permissions, assignable to users or to groups; it may carry `is_global`, and separately each assignment either names a resource or does not — one that does not is tenant-wide. **Resources** form a tree, and a role assigned on a parent cascades to its descendants. **Scopes** add sub-resource granularity where a permission needs to apply to only part of a resource.",
      },
      {
        type: "p",
        text: "Evaluation is **default-deny with deny-override**: nothing is permitted unless a grant allows it, and an explicit `effect: \"deny\"` refuses regardless of what else allows it — at any depth of the hierarchy and at equal specificity. See [the authorization engine](#/docs/authz) for the precedence table and why deny-override rather than most-specific-wins.",
      },
      {
        type: "note",
        text: "Earlier revisions of this page described the engine as additive-only with no explicit deny. That was accurate before deny grants shipped; it is not accurate now. Deny is a first-class effect on a permission grant.",
      },
      { type: "h", id: "sessions", text: "Sessions, tokens & credentials" },
      {
        type: "p",
        text: "Authenticating produces a **session**, identified by a `sid` that survives token refresh. Access tokens are short-lived EdDSA-signed JWTs; refresh tokens are opaque, server-stored and single-use. In a browser both live only in `httpOnly` cookies. Logging out ends the session — and, if relying parties are registered for back-channel logout, tells them so.",
      },
      { type: "h", id: "audit", text: "Everything is audited" },
      {
        type: "p",
        text: "Every authentication, authorization decision and administrative mutation is written to an append-only, cryptographically signed audit log. There are no UPDATE or DELETE paths on it. This is a property of the platform rather than a feature you enable.",
      },
      {
        type: "cards",
        cards: [
          {
            title: "Authorization engine →",
            body: "Precedence, cascade, scopes and how a decision is actually computed.",
            to: "docs",
            doc: "authz",
          },
          {
            title: "The security model →",
            body: "Threat model, cryptography and shared responsibility.",
            to: "security",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Roles, permissions & resources →",
            body: "The entities the engine evaluates over, and the API for each.",
            to: "docs",
            doc: "rbac",
          },
          {
            title: "Passwords, sessions & tokens →",
            body: "How a credential is verified, what comes back, and how a session ends.",
            to: "docs",
            doc: "auth",
          },
        ],
      },
    ],
  },

  {
    slug: "tutorial",
    section: "Getting started",
    navLabel: "Protect an app",
    title: "Tutorial — protect an app",
    intro:
      "One small service, protected end to end: sign a user in, guard a route, and check a permission on a real resource. From an empty machine to a request that is allowed because you granted it.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "shape", text: "What you are building" },
      {
        type: "p",
        text: "The [quickstart](#/docs/quickstart) gets a server running and makes one check with `curl`. [Core concepts](#/docs/concepts) explains what the pieces mean. This page is the bridge: a working service with the three things every protected application needs — a sign-in, a guard that rejects anonymous callers, and a per-request authorization check against a resource you created.",
      },
      {
        type: "p",
        text: "Two decisions are worth understanding before you start, because they are the ones people get wrong. **The guard and the check are different layers**: the guard establishes *who* is calling and fails with `401`; the check asks whether *that* caller may act on *this* resource and fails with `403`. And **the check is always made for the request's user**, never for the service account your application authenticated with — otherwise every user inherits your service's authority.",
      },
      { type: "h", id: "stack", text: "1. Bring the stack up" },
      {
        type: "p",
        text: "Dev infrastructure — SurrealDB and RabbitMQ — runs in Docker; the server builds with Rust. If you already have an AXIAM instance to point at, skip to step 3.",
      },
      {
        type: "code",
        caption: "terminal",
        code: "git clone https://github.com/ilpanich/axiam.git\ncd axiam\n\njust dev-up      # SurrealDB + RabbitMQ\njust build\njust run         # REST on :8090, gRPC on :50051",
      },
      {
        type: "code",
        code: "curl -s localhost:8090/health   # liveness — 200 whenever the process is up\ncurl -s localhost:8090/ready    # readiness — 200 only once SurrealDB answers",
      },
      {
        type: "note",
        text: "Wait for `/ready`, not `/health`. A server that is up but cannot reach its database will accept your bootstrap call and fail it, which looks like a bad request rather than a cold start.",
      },
      { type: "h", id: "bootstrap", text: "2. Create the organization and its admin" },
      {
        type: "p",
        text: "A fresh deployment has no users, and the endpoint that creates the first one is fail-closed — it refuses unless you prove you are the operator. Both gates and the seeded role set are on [First organization and admin](#/docs/bootstrap); the short version:",
      },
      {
        type: "code",
        caption: "terminal",
        code: "export AXIAM_BOOTSTRAP_ADMIN_EMAIL=admin@acme.dev   # set before starting the server\n\ncurl -X POST localhost:8090/api/v1/admin/bootstrap \\\n  -H 'content-type: application/json' \\\n  -d '{\n        \"organization_name\": \"Acme\",\n        \"organization_slug\": \"acme\",\n        \"email\": \"admin@acme.dev\",\n        \"username\": \"admin\",\n        \"password\": \"'\"$ADMIN_PASSWORD\"'\"\n      }'",
      },
      {
        type: "p",
        text: "That admin is **organization-level**: it lives in the organization's reserved scope and administers every tenant the organization will ever have. Bootstrap creates no ordinary tenant, so the next call is yours to make. Sign in with the tenant left blank — that is what resolves the organization scope — and create the tenant this tutorial works in:",
      },
      {
        type: "code",
        caption: "terminal",
        code: "TOKEN=$(curl -sS -X POST localhost:8090/api/v1/auth/login \\\n  -H 'content-type: application/json' \\\n  -d '{\"org_slug\":\"acme\",\"username_or_email\":\"admin\",\"password\":\"'\"$ADMIN_PASSWORD\"'\"}' \\\n  | jq -r .access_token)\n\n# `org_id` comes back on /auth/me, so no lookup is needed.\nORG=$(curl -sS localhost:8090/api/v1/auth/me \\\n  -H \"authorization: Bearer $TOKEN\" | jq -r .user.org_id)\n\ncurl -sS -X POST \"localhost:8090/api/v1/organizations/$ORG/tenants\" \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"name\":\"Production\",\"slug\":\"production\"}'",
      },
      {
        type: "note",
        text: "Creating a tenant seeds its permissions and its three default roles, and your organization-level admin already reaches it — no assignment is written, and none is needed. Every call in step 3 can therefore be made from this same session, adding `X-Axiam-Tenant: <the new tenant id>` to act on the tenant rather than on the organization scope. See [Organization-level principals](#/docs/organization-scope).",
      },
      { type: "h", id: "grant", text: "3. Create something to protect, and grant access to it" },
      {
        type: "p",
        text: "An authorization check needs a resource to be about and a grant that reaches it. Four calls — a resource, a permission, a role holding it, and the assignment that ties a user to the role — made against the tenant you just created, which means the same session with `X-Axiam-Tenant` naming it.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Create the resource",
            body: "Resources are hierarchical, and a role granted on a parent cascades to its children. Start with one node; the cascade is what you will lean on later.",
            code: "POST /api/v1/resources",
          },
          {
            title: "Create the permission",
            body: "A permission names an action on a resource type. This is the string your guard will ask about.",
            code: "POST /api/v1/permissions",
          },
          {
            title: "Create a role and attach the permission",
            body: "Roles are collections of permissions. Grant the narrow one you just made rather than reaching for the seeded admin role, which carries everything.",
            code: "POST /api/v1/roles\nPOST /api/v1/roles/{role_id}/permissions",
          },
          {
            title: "Assign the role to your test user",
            body: "Assign to a group instead and every member inherits it — the same grant, one indirection up.",
            code: "POST /api/v1/roles/{role_id}/users",
          },
        ],
      },
      {
        type: "note",
        text: "Nothing here grants anything by default. The engine is default-deny: a subject with no matching grant is refused, and an explicit deny anywhere in the resource tree overrides every allow at any depth. See [Deny overrides](#/docs/deny).",
      },
      { type: "h", id: "signin", text: "4. Sign a user in" },
      {
        type: "p",
        text: "The client takes a tenant **and** an organization: a tenant slug is only unique within an organization, so there is no default for either. Login has three outcomes, not two — success, MFA required, and MFA *setup* required when the tenant mandates MFA for an account that has none. Handle the third or those users cannot sign in at all.",
      },
      {
        type: "codegroup",
        caption: "sign in",
        tabs: [
          {
            label: "Rust",
            code: 'use axiam_sdk::client::AxiamClient;\n\nlet client = AxiamClient::builder()\n    .base_url("http://localhost:8090")?\n    .tenant_slug("production")\n    .org_slug("acme")\n    .build()?;\n\nlet login_result = client.login("user@acme.dev", &password).await?;\nif login_result.mfa_required {\n    client.verify_mfa("123456").await?;\n}',
          },
          {
            label: "TypeScript",
            code: "import { AxiamClient } from 'axiam-sdk';\n\nconst client = new AxiamClient({\n  baseUrl: 'http://localhost:8090',\n  tenantSlug: 'production',\n  orgSlug: 'acme',\n});\n\nconst result = await client.login(email, password);\nswitch (result.status) {\n  case 'authenticated':\n    console.log(`signed in as ${result.user.username}`);\n    break;\n  case 'mfa_required': {\n    const code = await promptForMfaCode(result.availableMethods);\n    await client.verifyMfa(result.mfaToken, code);\n    break;\n  }\n}",
          },
          {
            label: "Python",
            code: 'from axiam_sdk import AxiamClient\n\nclient = AxiamClient(\n    base_url="http://localhost:8090",\n    tenant_slug="production",\n    org_slug="acme",\n)\n\nresult = client.login("user@acme.dev", password)',
          },
        ],
      },
      { type: "h", id: "guard", text: "5. Guard the route" },
      {
        type: "p",
        text: "The guard verifies the caller's token against a locally cached JWKS — no round trip per request — and injects the authenticated identity into your handler. It must be told which tenant it is guarding: the JWKS trust anchor is organization-wide, so a verifier that does not pin a tenant would accept a sibling tenant's token.",
      },
      {
        type: "codegroup",
        caption: "authenticate every request",
        tabs: [
          {
            label: "Rust",
            code: '// Cargo.toml: features = ["actix"]\nuse axiam_sdk::middleware::AxiamUser;\n\n// Pin the tenant — §10.1 rule 4, fails closed without it.\nlet verifier = JwksVerifier::new(http, &base_url)?\n    .expect_tenant_id(tenant_uuid)\n    .expect_audience("axiam:user");\n\nasync fn protected(user: AxiamUser) -> String {\n    format!("hello {}", user.user_id)\n}',
          },
          {
            label: "TypeScript",
            code: "import express from 'express';\nimport { createNodeSession } from 'axiam-sdk/grpc';\nimport { axiamMiddleware, type AxiamRequest } from 'axiam-sdk/middleware';\n\nconst session = createNodeSession({ baseUrl: 'http://localhost:8090', tenantSlug: 'production' });\nconst app = express();\n\napp.use(axiamMiddleware(session));\n\napp.get('/protected', (req, res) => {\n  const user = (req as AxiamRequest).axiamUser;\n  res.json({ userId: user?.userId, roles: user?.roles });\n});",
          },
          {
            label: "Python",
            code: 'from fastapi import Depends, FastAPI\nfrom axiam_sdk.fastapi import AxiamUser, JwksVerifier, require_authenticated_user\n\nverifier = JwksVerifier(base_url)\nauthenticated_user = require_authenticated_user(verifier, "production")\n\napp = FastAPI()\n\n\n@app.get("/protected")\nasync def protected(user: AxiamUser = Depends(authenticated_user)):\n    return {"user_id": user.user_id, "roles": user.roles}',
          },
        ],
      },
      { type: "h", id: "check", text: "6. Check the permission" },
      {
        type: "p",
        text: "Authentication is not authorization. The declarative helpers add the per-endpoint check on top of the guard, resolving the resource id from the request — usually a path parameter — and asking the server whether *this* caller may perform *this* action on it.",
      },
      {
        type: "codegroup",
        caption: "authorize the request",
        tabs: [
          {
            label: "Rust",
            code: '// Cargo.toml: features = ["macros"]\nuse axiam_sdk::require_access;\nuse axiam_sdk::middleware::AxiamUser;\n\n#[require_access(action = "read", resource_param = "id")]\nasync fn get_document(user: AxiamUser) -> String {\n    format!("user {} may read this document", user.user_id)\n}',
          },
          {
            label: "TypeScript",
            code: "import { requireAccess, fromParam } from 'axiam-sdk/middleware';\n\napp.get(\n  '/documents/:id',\n  requireAccess(authzSession, 'read', fromParam('id')),\n  (req, res) => res.json({ documentId: req.params.id }),\n);",
          },
          {
            label: "Python",
            code: 'from axiam_sdk import AsyncAxiamClient\nfrom axiam_sdk.fastapi import AxiamUser, require_access\n\nauthz_client = AsyncAxiamClient(base_url=base_url, tenant_slug="production")\nrequire_doc_read = require_access(\n    verifier, "production", authz_client, "documents:read", resource_param="doc_id"\n)\n\n\n@app.get("/docs/{doc_id}")\nasync def get_doc(doc_id: str, user: AxiamUser = Depends(require_doc_read)):\n    return {"message": f"user {user.user_id} may read document {doc_id}"}',
          },
        ],
      },
      {
        type: "table",
        headers: ["Outcome", "Status", "Meaning"],
        rows: [
          ["Allowed", "your handler runs", "A grant matched and no deny overrode it."],
          ["Unauthenticated", "`401`", "No identity — the guard, not the check, refused."],
          ["Denied", "`403`", "Identity established, grant absent or overridden by a deny."],
          ["Unresolvable resource", "`400`", "The request named no resource the helper could resolve."],
          ["Authz unavailable", "`503`", "The check could not be made. **Fails closed** — never allowed on error."],
        ],
      },
      {
        type: "warn",
        text: "The role check that ships alongside these — `require_role` and its equivalents — is a local test against the verified token's roles, with no round trip. It is cheaper and coarser, and it is **not** a substitute for the resource-level check: it cannot see a deny on a child resource, and it does not know which resource the request is about.",
      },
      { type: "h", id: "verify", text: "7. Watch it refuse, then allow" },
      {
        type: "p",
        text: "The check is worth exercising in both directions, because a guard that never refuses is indistinguishable from one that is not wired up. Call the route as a user with no grant and expect `403`; assign the role from step 3 and call again.",
      },
      {
        type: "code",
        caption: "terminal",
        code: "# before the grant\ncurl -i -b cookies.txt localhost:3000/documents/$DOC_ID    # 403\n\n# after POST /api/v1/roles/{role_id}/users\ncurl -i -b cookies.txt localhost:3000/documents/$DOC_ID    # 200",
      },
      {
        type: "note",
        text: "No decision is cached by the helpers — every request is a fresh check — so a grant takes effect on the next call rather than on the next session. Sessions are a different matter: revoking a role does not retract a token already issued, which is what the short access-token lifetime and the revocation paths are for.",
      },
      { type: "h", id: "next", text: "Where to go next" },
      {
        type: "cards",
        cards: [
          {
            title: "Authorization engine →",
            body: "How a decision is actually computed: precedence, cascade and scopes.",
            to: "docs",
            doc: "authz",
          },
          {
            title: "Deny overrides →",
            body: "Why an explicit deny beats every allow, at any depth.",
            to: "docs",
            doc: "deny",
          },
          {
            title: "Client SDKs →",
            body: "The same three steps in the other eight languages.",
            to: "docs",
            doc: "sdks",
          },
        ],
      },
    ],
  },
];
