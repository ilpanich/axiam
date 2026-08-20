import type { DocPage } from "./types";

/**
 * "APIs & integration" — the three protocol surfaces, the provisioning and
 * eventing surfaces built on them, and the error taxonomy every SDK maps to.
 *
 * The error page is deliberately last and deliberately exhaustive: it is the
 * page somebody lands on from a stack trace, not one they read in order.
 */
export const INTEGRATE_PAGES: DocPage[] = [
  {
    slug: "rest",
    section: "APIs & integration",
    navLabel: "REST API",
    title: "REST API",
    intro:
      "The broadest surface — every entity in the system is manageable here, described by an OpenAPI 3.1 document that is generated from the server and drift-gated in CI.",
    blocks: [
      { type: "h", id: "spec", text: "The specification" },
      {
        type: "p",
        text: "`sdks/openapi.json` is the single source of truth for the REST surface. It is generated from the server's own route annotations, and a CI job fails any change where the committed spec diverges from a fresh export — so the document cannot quietly fall behind the code it describes.",
      },
      {
        type: "code",
        caption: "view it",
        code: "# any Swagger/Redoc viewer works\nnpx @redocly/cli preview-docs docs/api/openapi.json\n\n# or regenerate it after changing the API\ncargo build -p axiam-server --no-default-features\n./target/debug/axiam-server --dump-openapi > sdks/openapi.json",
      },
      {
        type: "note",
        text: "AXIAM deliberately does not serve an in-app Swagger UI route. Bundling one pulls a build-time download of the Swagger UI archive, which is a supply-chain and build-fragility cost for something every developer already has a viewer for.",
      },
      { type: "h", id: "shape", text: "Shape of the API" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Prefix", "What lives there"],
        rows: [
          [
            "`/api/v1/auth/*`",
            "Login, refresh, logout, password reset, email verification, MFA, WebAuthn, OPAQUE and federated sign-in.",
          ],
          [
            "`/api/v1/authz/*`",
            "Authorization checks, single and batched.",
          ],
          [
            "Entity collections",
            "`users`, `groups`, `roles`, `permissions`, `resources`, `service-accounts`, `oauth2-clients`, `organizations`, `tenants`, `certificates`, `pgp-keys`, `webhooks`, `reactors`, `notification-rules`, `federation-configs`, `scim-tokens`, `audit-logs`, `settings`.",
          ],
          ["`/oauth2/*`", "The authorization-server endpoints. See [OAuth2 & OIDC](#/docs/oauth2)."],
          ["`/uma2/*`", "The UMA 2.0 Protection API. See [UMA 2.0](#/docs/uma)."],
          ["`/scim/v2/*`", "SCIM 2.0 provisioning. See [SCIM provisioning](#/docs/scim)."],
          ["`/health`, `/ready`", "Liveness and readiness probes. See [Health & observability](#/docs/observability)."],
        ],
      },
      { type: "h", id: "conventions", text: "Conventions" },
      {
        type: "list",
        items: [
          "**Authentication** is `Authorization: Bearer <access_token>` — except in a browser, where the SDK uses `httpOnly` cookies and forwards a CSRF token.",
          "**Tenancy is explicit.** Entity routes are tenant-scoped through the authenticated principal; OAuth2 endpoints take `tenant_id` as a query parameter. Nothing is inferred from a default.",
          "**Every route is permission-guarded.** A caller needs an explicit grant for the action behind the route — the same 113-permission registry the admin console uses.",
          "**Collections paginate** with `offset` and `limit`, and return the items plus a total.",
          "**Mutations are audited.** Every write lands in the append-only audit log with the acting principal.",
        ],
      },
      { type: "h", id: "example", text: "A worked example" },
      {
        type: "code",
        caption: "create a user, put them in a group, check access",
        code: "TOKEN=$(curl -s -X POST https://iam.acme.dev/api/v1/auth/login \\\n  -H 'content-type: application/json' \\\n  -d '{\"org_slug\":\"acme\",\"tenant_slug\":\"production\",\n       \"username_or_email\":\"admin@acme.dev\",\"password\":\"...\"}' \\\n  | jq -r .access_token)\n\nUSER=$(curl -s -X POST https://iam.acme.dev/api/v1/users \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"email\":\"dana@acme.dev\",\"username\":\"dana\"}' | jq -r .id)\n\ncurl -X POST https://iam.acme.dev/api/v1/groups/$GROUP/members \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d \"{\\\"user_id\\\":\\\"$USER\\\"}\"\n\ncurl -X POST https://iam.acme.dev/api/v1/authz/check \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"action\":\"read\",\"resource_id\":\"doc:1\"}'",
      },
      { type: "h", id: "gdpr", text: "GDPR endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/account/export", summary: "Request a data export (GDPR Art. 15)." },
          { method: "GET", path: "/api/v1/account/export/{token}", summary: "Collect it, optionally PGP-encrypted." },
          { method: "POST", path: "/api/v1/account/delete", summary: "Request erasure (Art. 17)." },
          { method: "POST", path: "/api/v1/account/delete/cancel", summary: "Cancel a pending erasure inside the grace window." },
        ],
      },
      {
        type: "note",
        text: "Erasure pseudonymises the actor identity in the audit trail rather than deleting the records — an append-only log cannot have rows removed from it. The HMAC pepper that makes pseudonyms consistent is `AXIAM__GDPR_PSEUDONYM_PEPPER`; changing it breaks the linkage between old and new pseudonyms. See [Standards & compliance](#/docs/compliance).",
      },
    ],
  },

  {
    slug: "grpc",
    section: "APIs & integration",
    navLabel: "gRPC API",
    title: "gRPC API",
    intro:
      "A low-latency surface for service-mesh authorization checks, token validation and user lookups — Tonic on the server, one protobuf contract shared by every SDK.",
    blocks: [
      { type: "h", id: "why", text: "Why gRPC" },
      {
        type: "p",
        text: "REST is the general-purpose surface; gRPC exists for the hot path. Inside a service mesh, sidecars and backends make authorization checks on nearly every request, and connection reuse plus binary framing is what keeps tail latency down. In the benchmark run, a single gRPC `CheckAccess` held a p99 of 90 ms at database saturation, and TLS 1.3 cost nothing measurable against plaintext.",
      },
      { type: "h", id: "services", text: "Services" },
      {
        type: "p",
        text: "Defined in `proto/axiam/v1/`. Every request message is tenant-scoped — `tenant_id` is a field on every RPC, because there is no default tenant.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Service", "RPCs", "Purpose"],
        rows: [
          [
            "AuthorizationService",
            "CheckAccess, BatchCheckAccess",
            "A single access check, or several in one round trip.",
          ],
          [
            "TokenService",
            "ValidateToken, IntrospectToken",
            "Signature and expiry validation, or full RFC 7662-style claims.",
          ],
          [
            "UserService",
            "GetUser, ValidateCredentials",
            "Lookup by id, or a username/password check that issues no token.",
          ],
        ],
      },
      { type: "h", id: "server", text: "The server" },
      {
        type: "p",
        text: "The gRPC listener starts inside `axiam-server` alongside REST and the AMQP consumer. It binds `127.0.0.1:50051` by default — loopback only — and is meant to be reached in-cluster over an internal network or mTLS, never through a public ingress. Bind address, port and the per-IP rate limit are the `AXIAM__GRPC__*` variables.",
      },
      {
        type: "note",
        text: "In the shipped Kubernetes manifests, port 50051 is intentionally *not* routed through the Ingress — it is reachable only via the in-cluster ClusterIP service.",
      },
      { type: "h", id: "consume", text: "Consuming it" },
      {
        type: "p",
        text: "The seven SDKs implementing the full contract — Rust, TypeScript, Python, Java, C#, PHP and Go — ship pre-generated stubs, so you consume gRPC without running codegen. The call surface mirrors the `can()` / `canAll()` you already know.",
      },
      {
        type: "code",
        caption: "authorization check over gRPC · Rust",
        code: "use axiam_sdk::AxiamClient;\n\nlet axiam = AxiamClient::builder()\n    .base_url(\"https://iam.acme.dev\")\n    .org_slug(\"acme\")\n    .tenant_slug(\"production\")\n    .grpc(true) // route checks over the gRPC transport\n    .build()?;\n\nlet ok = axiam.can(\"read\", \"doc:1\").await?;",
      },
      { type: "h", id: "codegen", text: "Generating your own stubs" },
      {
        type: "p",
        text: "Integrating from a language with no published AXIAM SDK? Generate stubs straight from the `.proto` files with `buf generate`, or `protoc` plus your language's gRPC plugin. They are self-contained proto3 with no imports beyond the well-known types, and CI runs `buf lint` and `buf breaking` on every change — so the contract is guarded against accidental breakage.",
      },
      { type: "code", code: "buf generate   # from the vendored proto/ tree" },
      {
        type: "note",
        text: "The Kotlin, Swift, C and C++ SDKs cover the REST surface today; gRPC is a planned follow-up for them. Until it lands, use the REST transport or generate stubs directly from `proto/`.",
      },
    ],
  },

  {
    slug: "amqp",
    section: "APIs & integration",
    navLabel: "AMQP & async",
    title: "AMQP — asynchronous authorization & events",
    intro:
      "The message bus behind deferred authorization decisions, audit ingestion, mail, webhook delivery and Reactor hooks — specified as AsyncAPI 2.6.",
    blocks: [
      { type: "h", id: "why", text: "What runs over the bus" },
      {
        type: "p",
        text: "Some work should not happen on a request thread. Audit ingestion must not slow down the operation being audited; webhook delivery must survive a receiver being down; a mail send must not fail a signup. AXIAM puts all of it on RabbitMQ, and exposes the same authorization engine there for callers that want a decision without holding a connection open.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Channel", "Purpose"],
        rows: [
          ["axiam.authz.request", "Deferred authorization requests."],
          ["axiam.authz.response", "The decisions, correlated back to the requester."],
          ["axiam.audit.events", "Audit ingestion, off the request hot path."],
          ["axiam.notifications", "Notification-rule delivery."],
          ["axiam.mail.outbound", "Outbound mail — verification, reset, alerts."],
          ["axiam.webhook", "Webhook delivery, with `axiam.webhook.retry` for backoff."],
        ],
      },
      {
        type: "p",
        text: "Each has a dead-letter queue (`*.dlq`) for messages that exhaust their retries, so a permanently-failing consumer produces an inspectable backlog rather than silent loss.",
      },
      { type: "h", id: "security", text: "Transport security & authenticity" },
      {
        type: "warn",
        text: "AMQP is **TLS-only**. `AXIAM__AMQP__URL` must use the `amqps://` scheme — every other scheme is refused at startup rather than downgraded.",
      },
      {
        type: "p",
        text: "Message authenticity is an HMAC over the whole message with replay protection — a nonce plus a freshness window — not merely a signature over the body. This matters because a bus consumer cannot rely on TLS peer identity the way an HTTP caller can: the broker is in between.",
      },
      { type: "h", id: "spec", text: "The specification" },
      {
        type: "p",
        text: "`docs/api/asyncapi.yml` is a hand-authored AsyncAPI 2.6 document covering every channel, its message schema and its DLQ. The normative HMAC construction is `sdks/CONTRACT.md` §8 and §8b, which every SDK implements identically.",
      },
      {
        type: "note",
        text: "Reactors also ride this bus, but with a different contract: a Reactor can *answer* — allow, deny, or a narrowly field-allow-listed mutation — inside a timeout the server declares. See [Reactors](#/docs/reactors).",
      },
    ],
  },

  {
    slug: "scim",
    section: "APIs & integration",
    navLabel: "SCIM provisioning",
    title: "SCIM 2.0 provisioning",
    intro:
      "Let Okta, Microsoft Entra ID or any SCIM-compliant IdP create, update and deactivate AXIAM users and groups directly, instead of an administrator doing it by hand.",
    blocks: [
      { type: "h", id: "why", text: "Federation is not provisioning" },
      {
        type: "p",
        text: "Federation answers *who is this person* at sign-in. It does not create an account before someone's first day, does not update it when they change teams, and — the one that matters — does not deactivate it when they leave. SCIM does all three, driven by the directory that already knows.",
      },
      { type: "h", id: "support", text: "What is implemented" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Area", "Support"],
        rows: [
          ["Users", "Full CRUD plus PATCH."],
          ["Groups", "Full CRUD plus PATCH, including membership."],
          [
            "Filtering",
            "`userName eq \"...\"` on Users, `externalId eq \"...\"` on Users and Groups, and paging with `startIndex` / `count`.",
          ],
          [
            "PATCH operations",
            "`add` / `replace` / `remove` on the standard attribute paths Okta and Entra actually send.",
          ],
          ["Discovery", "`/Schemas`, `/ServiceProviderConfig`, `/ResourceTypes`."],
          ["Bulk operations", "**Not supported** — `POST /Bulk` returns `501` with a SCIM error body."],
          [
            "Complex filters",
            "**Not supported** — anything other than `<attr> eq \"<value>\"` returns `400 invalidFilter`.",
          ],
          ["ETag / conditional requests", "**Not implemented**, and `ServiceProviderConfig` says so."],
        ],
      },
      {
        type: "note",
        text: "The unsupported items are the two the specification itself carves out as optional, and the two no mainstream IdP requires for user and group lifecycle. Enterprise IdP-driven provisioning is mostly CRUD.",
      },
      { type: "h", id: "endpoints", text: "Endpoints" },
      {
        type: "code",
        code: "GET    /scim/v2/ServiceProviderConfig\nGET    /scim/v2/ResourceTypes\nGET    /scim/v2/Schemas\n\nGET    /scim/v2/Users?filter=...&startIndex=1&count=50\nPOST   /scim/v2/Users\nGET    /scim/v2/Users/{id}\nPUT    /scim/v2/Users/{id}\nPATCH  /scim/v2/Users/{id}\nDELETE /scim/v2/Users/{id}\n\nGET    /scim/v2/Groups?filter=...&startIndex=1&count=50\nPOST   /scim/v2/Groups\nGET    /scim/v2/Groups/{id}\nPUT    /scim/v2/Groups/{id}\nPATCH  /scim/v2/Groups/{id}\nDELETE /scim/v2/Groups/{id}",
      },
      { type: "h", id: "tokens", text: "Authentication & tenant scoping" },
      {
        type: "p",
        text: "A SCIM client authenticates with a dedicated provisioning token, bound to one tenant and carrying a dedicated permission — not a super-admin session, and not an OAuth2 client secret reused for something else. An IdP integration that is compromised should be able to manage users in one tenant and nothing else.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/scim-tokens", summary: "List provisioning tokens for the tenant." },
          { method: "POST", path: "/api/v1/scim-tokens", summary: "Mint one. The value is returned exactly once." },
          { method: "DELETE", path: "/api/v1/scim-tokens/{id}", summary: "Revoke one." },
        ],
      },
      {
        type: "warn",
        text: "Deactivation, not deletion, is what you usually want from an IdP. A SCIM `DELETE` removes the account; setting `active: false` disables sign-in while leaving the identity intact for the audit trail. Configure your IdP's deprovisioning action deliberately.",
      },
      {
        type: "note",
        text: "Step-by-step walkthroughs for wiring up Okta and Microsoft Entra ID are in `docs/api/scim-provisioning.md` in the repository.",
      },
    ],
  },

  {
    slug: "webhooks",
    section: "APIs & integration",
    navLabel: "Webhooks",
    title: "Webhooks",
    intro:
      "Fire-and-forget HTTP callbacks on domain events, signed so a receiver can prove they came from AXIAM.",
    blocks: [
      { type: "h", id: "delivery", text: "Signed delivery" },
      {
        type: "p",
        text: "A webhook delivers an event notification to an endpoint you configure, as an outbound HTTPS POST. Every payload is signed with HMAC-SHA256 over the raw body, so a receiver can confirm the request genuinely came from AXIAM and was not altered in transit.",
      },
      {
        type: "p",
        text: "Delivery is **at-least-once**, over the AMQP bus, with retry and exponential backoff and a dead-letter queue after `max_attempts`. Your receiver must therefore be idempotent — nothing here promises exactly-once, and a broker hiccup is a redelivery.",
      },
      { type: "h", id: "verify", text: "Verifying a payload" },
      {
        type: "p",
        text: "Compute the HMAC-SHA256 of the **raw** request body with your endpoint's shared secret and compare it in constant time against the signature header. Parse the body only after the comparison succeeds.",
      },
      {
        type: "codegroup",
        caption: "signature verification",
        tabs: [
          {
            label: "Node",
            code: "import { createHmac, timingSafeEqual } from 'node:crypto';\n\nfunction verify(rawBody, signature, secret) {\n  const expected = createHmac('sha256', secret)\n    .update(rawBody)\n    .digest('hex');\n  return expected.length === signature.length &&\n    timingSafeEqual(Buffer.from(expected), Buffer.from(signature));\n}",
          },
          {
            label: "Python",
            code: "import hmac, hashlib\n\ndef verify(raw_body: bytes, signature: str, secret: str) -> bool:\n    expected = hmac.new(\n        secret.encode(), raw_body, hashlib.sha256\n    ).hexdigest()\n    return hmac.compare_digest(expected, signature)",
          },
          {
            label: "Go",
            code: "func verify(rawBody []byte, signature, secret string) bool {\n    mac := hmac.New(sha256.New, []byte(secret))\n    mac.Write(rawBody)\n    expected := hex.EncodeToString(mac.Sum(nil))\n    return hmac.Equal([]byte(expected), []byte(signature))\n}",
          },
        ],
      },
      {
        type: "warn",
        text: "Compare in constant time, and compare against the **raw** bytes. Re-serialising the parsed JSON and hashing that will not match — key order and whitespace are part of what was signed.",
      },
      { type: "h", id: "managing", text: "Managing webhooks" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/webhooks", summary: "List configured webhooks." },
          { method: "POST", path: "/api/v1/webhooks", summary: "Create one, subscribing to a list of event types." },
          { method: "GET", path: "/api/v1/webhooks/{id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/webhooks/{id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/webhooks/{id}", summary: "Delete it." },
          { method: "GET", path: "/api/v1/reactors/events", summary: "The event catalog — every event type that can be subscribed to." },
        ],
      },
      {
        type: "p",
        text: "A webhook subscribes to a list of event type names — `user.created` and `auth.login` are typical. The catalog is a growing list rather than a fixed enum; query `/api/v1/reactors/events` for what this build actually emits rather than hard-coding a list from documentation.",
      },
      {
        type: "note",
        text: "Webhook secrets are encrypted at rest under `AXIAM__PKI__ENCRYPTION_KEY`, alongside the CA signing keys.",
      },
      { type: "h", id: "vs", text: "Webhook or Reactor?" },
      {
        type: "p",
        text: "A webhook is told what happened, after it happened, and cannot affect it. If you need to *influence* an operation — approve it, refuse it, or adjust a narrowly allow-listed field before it commits — that is a Reactor. See [Reactors](#/docs/reactors).",
      },
    ],
  },

  {
    slug: "reactors",
    section: "APIs & integration",
    navLabel: "Reactors",
    title: "Reactors — external hook actors",
    intro:
      "An external process that subscribes to authorization-adjacent hook events and answers back — allow, deny, or a narrowly allow-listed mutation — inside a timeout the server declared.",
    blocks: [
      { type: "h", id: "what", text: "What a Reactor is" },
      {
        type: "p",
        text: "A Reactor is AXIAM's answer to Zitadel Actions and Keycloak SPIs, and the difference is the whole design: those load third-party code **into** the authorization server. A Reactor stays outside, reachable only over the AMQP bus, and answers through a signed reply schema the server validates before it believes a word of it.",
      },
      {
        type: "p",
        text: "That boundary is what makes the feature safe to have. A crashing, hanging or malicious Reactor cannot take the authorization server with it — it can, at worst, fail its own hook inside the declared timeout, and the configured failure policy decides what that means.",
      },
      { type: "h", id: "modes", text: "Two modes" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["", "Webhook", "Listener Reactor (`mode: \"listen\"`)"],
        rows: [
          ["Transport", "Outbound HTTPS POST to a URL", "AMQP consume from a durable, server-declared queue"],
          [
            "Authenticity",
            "HMAC-SHA256 over the body",
            "HMAC over the whole message, replay-protected with a nonce and freshness window",
          ],
          [
            "Delivery",
            "At-least-once with retry, backoff and a DLQ",
            "At-least-once — **your consumer must be idempotent**",
          ],
          [
            "Event catalog",
            "Domain events: `user.created`, `role.assigned`, … a fixed, growing list",
            "Any event in the reactor registry, **including non-interceptable ones**",
          ],
          [
            "Can it affect the operation?",
            "Never — the change is already committed when it fires",
            "Never, by construction — the server does not wait for a listener's reply",
          ],
        ],
      },
      {
        type: "p",
        text: "The other mode intercepts: the server waits, within its declared timeout, and the Reactor's validated reply can allow, deny, or apply a mutation limited to an explicitly allow-listed set of fields.",
      },
      { type: "h", id: "failure", text: "Failure policy is the decision that matters" },
      {
        type: "warn",
        text: "An intercepting Reactor sits in the path of a real operation. Its failure policy decides what happens when it times out or answers unintelligibly — fail open (proceed) or fail closed (refuse). Fail-closed turns a Reactor outage into an outage of whatever it hooks; fail-open turns it into a silently unenforced control. Choose deliberately, and monitor either way.",
      },
      { type: "h", id: "registering", text: "Registering one" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/reactors", summary: "List registered Reactors." },
          { method: "POST", path: "/api/v1/reactors", summary: "Register one." },
          { method: "GET", path: "/api/v1/reactors/{id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/reactors/{id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/reactors/{id}", summary: "Remove it." },
          { method: "GET", path: "/api/v1/reactors/events", summary: "The event registry — what can be hooked, and which events are interceptable." },
        ],
      },
      {
        type: "note",
        text: "The wire protocol — message shape, signing, the reply schema and the timeout semantics — is normative in `sdks/CONTRACT.md` §22. The admin console's Reactors page is the same surface with a form on top.",
      },
    ],
  },

  {
    slug: "errors",
    section: "APIs & integration",
    navLabel: "Error reference",
    title: "Error reference",
    intro:
      "Three error types across every SDK and every language, one mapping from HTTP and gRPC status, and the handful of rules that keep a client from retrying something that cannot succeed.",
    blocks: [
      { type: "h", id: "types", text: "The three types" },
      {
        type: "p",
        text: "Every SDK exposes exactly three error types. Languages add idiomatic sub-types, but never replace these three — so an integration ported between languages keeps the same control flow.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Type", "Meaning"],
        rows: [
          [
            "AuthError",
            "Authentication failure: wrong credentials, expired session, failed MFA, a 401 on refresh.",
          ],
          ["AuthzError", "Authorization failure: the caller lacks permission for the requested operation."],
          [
            "NetworkError",
            "Transport-level failure: connection refused, timeout, TLS error, DNS failure.",
          ],
          [
            "OAuthProtocolError",
            "A **sub-type of `AuthError`**. An RFC 6749 protocol error from an `/oauth2/*` endpoint, carrying `error` and `error_description` as accessible fields.",
          ],
        ],
      },
      { type: "h", id: "http", text: "HTTP status mapping" },
      {
        type: "table",
        headers: ["Status", "Type", "Notes"],
        rows: [
          ["400", "NetworkError", "Malformed request — an SDK or caller programming error."],
          [
            "any status from /oauth2/* with an OAuth2 error body",
            "OAuthProtocolError",
            "**Dispatch on the `error` field, not on the status.** This row wins over the status rows below.",
          ],
          ["401", "AuthError", "Unauthenticated. Triggers single-flight refresh when tokens are present."],
          ["403", "AuthzError", "Authenticated but not authorized."],
          ["408, 429", "NetworkError", "Timeout, or rate-limited."],
          ["409", "AuthzError", "Conflict — resource-level access denied."],
          ["5xx", "NetworkError", "Server error. An SDK must **not** retry authentication."],
          ["connection / DNS / TLS failure", "NetworkError", "Carries the underlying transport error as its cause."],
        ],
      },
      {
        type: "warn",
        text: "The `/oauth2/*` row is scoped to those paths only. An ordinary REST `403` — including from `/api/v1/authz/check` and from the UMA Protection API at `/uma2/*` — is an `AuthzError`, not a protocol error. The distinction matters: one is *you may not*, the other is *your client credentials or grant request were wrong*.",
      },
      { type: "h", id: "grpc", text: "gRPC status mapping" },
      {
        type: "table",
        headers: ["gRPC status", "Type", "Notes"],
        rows: [
          ["UNAUTHENTICATED (16)", "AuthError", "Triggers single-flight refresh."],
          ["PERMISSION_DENIED (7)", "AuthzError", "Caller lacks the required permission."],
          ["UNAVAILABLE (14)", "NetworkError", "Server unreachable."],
          ["DEADLINE_EXCEEDED (4)", "NetworkError", "Request timed out."],
          ["INTERNAL (13)", "NetworkError", "Server-side error."],
          ["RESOURCE_EXHAUSTED (8)", "NetworkError", "Rate-limited."],
        ],
      },
      { type: "h", id: "rules", text: "Rules that prevent bad retries" },
      {
        type: "list",
        items: [
          "**A 401 carrying an OAuth2 protocol error does not enter the refresh guard.** A client-authentication failure is not a session expiry, and retrying cannot fix a wrong client secret.",
          "**Concurrent 401s collapse into one refresh.** The single-flight guard means N in-flight requests produce one refresh attempt, not N.",
          "**Errors never contain token strings** — not in messages, not in context fields, not in stack traces.",
          "**`AuthzError` carries the denied action and resource** where the response body provides them, so a log line says what was refused rather than only that something was.",
        ],
      },
      { type: "h", id: "device", text: "Device-grant answers" },
      {
        type: "p",
        text: "The device grant's four answers are protocol errors with specific reactions rather than failures — see [Device authorization grant](#/docs/device-flow) for the table. `authorization_pending` and `slow_down` are normal, expected control flow.",
      },
      {
        type: "note",
        text: "The normative source for all of this is `sdks/CONTRACT.md` §2, which every SDK is conformance-tested against. If this page and that chapter ever disagree, the contract is authoritative.",
      },
    ],
  },
];
