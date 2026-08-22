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
          "**Two ways to authenticate.** A machine client sends `Authorization: Bearer <access_token>`, obtained from the OAuth2 token endpoint. An interactive login sets `httpOnly` cookies instead — `POST /auth/login` returns no token in its body — and state-changing requests must then echo the `axiam_csrf` cookie in an `X-CSRF-Token` header. The SDKs handle the second case for you.",
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
        code: "# A machine client gets a bearer token from the OAuth2 token endpoint.\n# (An interactive login sets cookies instead — see the Quickstart.)\nTOKEN=$(curl -sS -X POST 'https://iam.acme.dev/oauth2/token?tenant_id=<uuid>' \\\n  -d grant_type=client_credentials \\\n  -d client_id=\"$SA_CLIENT_ID\" -d client_secret=\"$SA_CLIENT_SECRET\" \\\n  | jq -r .access_token)\n\nUSER=$(curl -sS -X POST https://iam.acme.dev/api/v1/users \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"email\":\"dana@acme.dev\",\"username\":\"dana\"}' | jq -r .id)\n\ncurl -sS -X POST \"https://iam.acme.dev/api/v1/groups/$GROUP/members\" \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d \"{\\\"user_id\\\":\\\"$USER\\\"}\"\n\ncurl -sS -X POST https://iam.acme.dev/api/v1/authz/check \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"action\":\"read\",\"resource_id\":\"doc:1\"}'",
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
        text: "The seven SDKs implementing the full contract — Rust, TypeScript, Python, Java, C#, PHP and Go — ship pre-generated stubs, so you consume gRPC without running codegen yourself. gRPC is a **separate client** rather than a flag on the REST one — it is a different transport, with its own channel, TLS settings and connection lifetime — but it shares the session and the single-flight refresh guard, and the decisions it returns are the same ones REST returns.",
      },
      {
        type: "code",
        caption: "building a gRPC channel · Rust",
        code: "use axiam_sdk::grpc::{build_channel, GrpcChannelConfig};\n\n// gRPC is a separate channel rather than a flag on the REST client: it is a\n// different transport with its own TLS and connection settings.\nlet channel = build_channel(\n    \"https://iam.acme.dev:50051\",\n    &GrpcChannelConfig::default(),\n)?;\n\n// The channel then backs `AuthzGrpcClient`, which shares the REST client's\n// single-flight refresh guard. See the SDK's `grpc_check_access` example.",
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
      "Fire-and-forget HTTP callbacks on domain events, signed with a timestamped HMAC so a receiver can prove they came from AXIAM and reject a replay.",
    blocks: [
      { type: "h", id: "delivery", text: "Signed delivery" },
      {
        type: "p",
        text: "A webhook delivers an event notification to an endpoint you configure, as an outbound HTTPS POST. Delivery is **at-least-once**: the server queues each delivery on a durable AMQP topology, retries with exponential backoff, and dead-letters what never succeeds. Your receiver must be idempotent — nothing here promises exactly-once, and a retry replays a validly signed request.",
      },
      {
        type: "p",
        text: "Every attempt goes through the same SSRF guard the federation client uses: the host is resolved fresh, a private, loopback or link-local address is refused, the validated IP is pinned into the connection so nothing can re-resolve between the check and the send, and a non-HTTPS target is treated as blocked. The shared secret is stored AES-256-GCM encrypted under `AXIAM__PKI__ENCRYPTION_KEY`, is never returned by any endpoint, and is decrypted in memory only to compute a signature — with no key configured the subsystem fails closed with a `503` rather than delivering unsigned.",
      },
      { type: "h", id: "headers", text: "What arrives" },
      {
        type: "table",
        headers: ["Header", "Value"],
        rows: [
          ["X-Axiam-Signature", "`t=<unix_seconds>,v1=<hex_lowercase>`"],
          ["X-Axiam-Timestamp", "unix seconds, decimal — the same value as `t=`"],
          ["X-Axiam-Event", "the event type, e.g. `user.created`"],
          ["X-Axiam-Delivery", "delivery UUID — the at-least-once dedup key"],
        ],
      },
      {
        type: "p",
        text: "`v1` is `HMAC-SHA256(secret, \"<timestamp>.<raw_body>\")`, hex-encoded lowercase, where `<timestamp>` is byte-identical to the `t=` field. Binding the timestamp into the signed string is what lets a receiver enforce a replay window: a captured delivery replayed an hour later carries a valid MAC over a timestamp that is now stale.",
      },
      {
        type: "code",
        caption: "a delivery, on the wire",
        code: `POST /webhooks/axiam HTTP/1.1
Content-Type: application/json
X-Axiam-Timestamp: 1785700000
X-Axiam-Signature: t=1785700000,v1=3f2b…c91d
X-Axiam-Event: user.created
X-Axiam-Delivery: 018f3c2a-8f11-7b0e-9a54-2c1f7d3e5b90

{"id":"018f3c2a-…","username":"alice"}`,
      },
      {
        type: "note",
        text: "The body is the **event payload itself** — there is no envelope around it. The event type and the delivery id travel in headers, so read them there rather than expecting them in the JSON.",
      },
      { type: "h", id: "verify", text: "Verifying a delivery" },
      {
        type: "p",
        text: "Every SDK ships the verifier, so this is not a thing to hand-roll: `verify_webhook` in Rust and Python, `verifyWebhook` in TypeScript, `AxiamWebhooks.verify` in Java, Kotlin and Swift, `AxiamWebhooks.Verify` in C#, `AxiamWebhooks::verify` in PHP, `webhook.Verify` in Go, `axiam_webhook_verify` in C and `axiam::webhook::verify` in C++. Each takes the secret, the raw `X-Axiam-Signature` value, the raw body bytes and an optional tolerance defaulting to **300 s**, compares in constant time, and fails closed and quiet — the error never carries the expected signature.",
      },
      {
        type: "codegroup",
        caption: "verifying a delivery",
        tabs: [
          {
            label: "TypeScript",
            code: `import { verifyWebhook, WebhookVerifyError } from 'axiam-sdk';

app.post('/webhooks/axiam', (req, res) => {
  try {
    // req.rawBody is the exact bytes off the wire — express.json() alone
    // discards them; capture them with its verify callback.
    verifyWebhook(secret, req.header('X-Axiam-Signature'), req.rawBody);
  } catch (err) {
    if (err instanceof WebhookVerifyError) return res.status(400).end();
    throw err;
  }

  const type = req.header('X-Axiam-Event');
  const deliveryId = req.header('X-Axiam-Delivery');   // dedup on this
  res.status(200).end();
});`,
          },
          {
            label: "Python",
            code: `from axiam_sdk.webhook import WebhookVerifyError, verify_webhook

@app.post("/webhooks/axiam")
def axiam_webhook():
    try:
        event = verify_webhook(
            secret=WEBHOOK_SECRET,
            signature_header=request.headers["X-Axiam-Signature"],
            body=request.get_data(),          # raw bytes, NOT re-serialized JSON
            event_type=request.headers.get("X-Axiam-Event"),
            delivery_id=request.headers.get("X-Axiam-Delivery"),
        )
    except WebhookVerifyError:
        return "invalid signature", 400

    # event.delivery_id is the at-least-once dedup key.
    return "", 200`,
          },
          {
            label: "Go",
            code: `body, err := io.ReadAll(r.Body)
if err != nil {
    http.Error(w, "failed to read body", http.StatusBadRequest)
    return
}

if _, err := webhook.Verify(
    axiam.Sensitive(webhookSecret),
    r.Header.Get("X-Axiam-Signature"),
    body,
); err != nil {
    http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
    return
}

deliveryID := r.Header.Get("X-Axiam-Delivery")   // dedup on this
w.WriteHeader(http.StatusOK)`,
          },
        ],
      },
      {
        type: "warn",
        text: "**Verify the raw bytes.** Re-serialising the parsed JSON and hashing that will not match — key order and whitespace are part of what was signed, and most JSON body parsers discard the original bytes by default. Parse only after the comparison succeeds, take `t=` from the signature header rather than from `X-Axiam-Timestamp` (only the former is covered by the MAC), and treat a header with no `v1` as a failure rather than as nothing to check.",
      },
      { type: "h", id: "events", text: "The event catalog" },
      {
        type: "p",
        text: "A webhook subscribes to a list of event-type names. Three are emitted today, from the user-management endpoints and from SCIM provisioning alike, so an IdP-driven provisioning run raises the same events as an API call:",
      },
      {
        type: "table",
        headers: ["Event", "Raised when", "Payload"],
        rows: [
          ["user.created", "A user is created through `POST /api/v1/users` or SCIM provisioning", "`id`, `username`"],
          ["user.updated", "A user is updated through the API, SCIM `PUT` or SCIM `PATCH`", "`id`, `username`"],
          ["user.deleted", "A user is deleted through the API or deprovisioned through SCIM", "`id`"],
        ],
      },
      {
        type: "note",
        text: "The subscription list is not validated against a catalog — it must be non-empty, and that is all. Subscribing to a name the server does not raise is accepted and simply never fires, so treat a silent webhook as a possible typo before treating it as a delivery failure. The catalog is expected to grow; a delivery you do not recognise should be ignored rather than rejected.",
      },
      { type: "h", id: "retry", text: "Retry, backoff and the dead-letter queue" },
      {
        type: "p",
        text: "Retry scheduling belongs to the broker, not to a sleeping task. A delivery is published to `axiam.webhook`; a failed attempt is republished to `axiam.webhook.retry` with a per-message TTL and no consumer attached, so when the TTL expires RabbitMQ dead-letters it back onto `axiam.webhook` for the next attempt. Once the attempts are exhausted the delivery lands on `axiam.webhook.dlq`, where it is real and replayable rather than silently dropped. Every attempt and every terminal outcome is written to the audit log.",
      },
      {
        type: "table",
        headers: ["Config key", "Default", "Meaning"],
        rows: [
          [
            "AXIAM__WEBHOOK__MAX_ATTEMPTS",
            "`5`",
            "Total delivery attempts before the message is dead-lettered; the first attempt counts as one.",
          ],
          [
            "AXIAM__WEBHOOK__BACKOFF_BASE_MS",
            "`5000`",
            "Delay before the first retry.",
          ],
          [
            "AXIAM__WEBHOOK__BACKOFF_CEILING_MS",
            "`3600000`",
            "Upper bound on any single retry delay — one hour.",
          ],
        ],
      },
      {
        type: "p",
        text: "The delay is `base × 2^(attempt − 1)`, clamped to the ceiling — 5 s, 10 s, 20 s, 40 s on the defaults. The multiplier is fixed at 2 and is not configurable.",
      },
      {
        type: "warn",
        text: "A webhook also carries a per-endpoint `retry_policy` (`max_retries`, `initial_delay_secs`, `backoff_multiplier`), which is validated and stored — `max_retries` at most 10, `initial_delay_secs` between 1 and 3600, `backoff_multiplier` between 0 and 10. The delivery consumer does **not** read it: the schedule that runs is the deployment-wide one above. Treat the field as recorded intent, not as a per-endpoint control.",
      },
      { type: "h", id: "managing", text: "Managing webhooks" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/webhooks", summary: "List configured webhooks. The secret is never included." },
          { method: "POST", path: "/api/v1/webhooks", summary: "Create one, subscribing to a list of event types." },
          { method: "GET", path: "/api/v1/webhooks/{id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/webhooks/{id}", summary: "Update the URL, the subscription, the enabled flag or the secret." },
          { method: "DELETE", path: "/api/v1/webhooks/{id}", summary: "Delete it." },
        ],
      },
      {
        type: "code",
        caption: "POST /api/v1/webhooks",
        code: `{
  "url": "https://hooks.example.com/axiam",
  "events": ["user.created", "user.updated", "user.deleted"],
  "secret": "whsec_…",
  "retry_policy": { "max_retries": 5, "initial_delay_secs": 10, "backoff_multiplier": 2.0 }
}`,
      },
      {
        type: "p",
        text: "The URL must be HTTPS and must resolve to a globally routable address — a private, loopback or link-local target is refused at creation as well as at delivery. Every endpoint is permission-gated (`webhooks:create`, `webhooks:list`, `webhooks:get`, `webhooks:update`, `webhooks:delete`).",
      },
      { type: "h", id: "rotation", text: "Rotating a secret" },
      {
        type: "p",
        text: "AXIAM signs each delivery with exactly one secret and sends exactly one `v1` value, so there is no overlap window on the server side. The overlap has to live in your receiver, which is why the order below matters: the secret is read fresh on every attempt, so a delivery still being retried when you rotate is re-signed with the new secret.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Generate the new secret",
            body: "Use a high-entropy random value. It is a MAC key, not a password — length beats memorability, and nothing ever needs to type it.",
          },
          {
            title: "Teach the receiver to accept either",
            body: "Verify against the new secret and fall back to the old one on failure, using the same SDK helper twice. Deploy this **before** rotating, so no delivery arrives with a secret your receiver has never heard of.",
          },
          {
            title: "Rotate on the server",
            body: "`PUT` the webhook with the new `secret`. It is encrypted with AES-256-GCM before storage and never returned in a response, so this is also the only way to change it — there is no read-back.",
            code: `PUT /api/v1/webhooks/{id}
{ "secret": "whsec_new_…" }`,
          },
          {
            title: "Wait out the retry window, then drop the old secret",
            body: "Anything still in flight is re-signed with the new secret on its next attempt, so the fallback is only needed for deliveries already accepted by your receiver. Give it the worst-case retry span — `MAX_ATTEMPTS` attempts of backoff, up to the ceiling — before removing the old key, then redeploy with the single new secret.",
          },
        ],
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
      { type: "h", id: "registry", text: "The five hookable events" },
      {
        type: "p",
        text: "The registry is data, not prose: it lives in [EVENT_REGISTRY](https://github.com/ilpanich/axiam/blob/main/crates/axiam-core/src/models/reactor.rs), in `crates/axiam-core/src/models/reactor.rs`, and is served live at `GET /api/v1/reactors/events`, which is the copy a tool should read — the REST layer validates a registration against it and the dispatcher validates a reply against it, so there is one source and no second list to drift. The table below is that data as of this release.",
      },
      {
        type: "table",
        headers: ["Event", "Interceptable", "A patch may set", "Default failure policy", "Purpose"],
        rows: [
          [
            "token.pre_issue",
            "yes",
            "the `ext.` namespace only",
            "`fail_open`",
            "Enrich or veto token issuance. May add claims under `ext.` only.",
          ],
          [
            "login.post_auth",
            "yes",
            "nothing — veto, or `require_mfa`",
            "`fail_closed`",
            "After credentials verify, before session issuance: veto or require step-up MFA.",
          ],
          [
            "user.pre_create",
            "yes",
            "`username`, `email`, the `metadata.` namespace",
            "`fail_closed`",
            "Validate or normalize a new user's profile fields.",
          ],
          [
            "user.pre_update",
            "yes",
            "`username`, `email`, the `metadata.` namespace",
            "`fail_closed`",
            "Validate or normalize a profile update.",
          ],
          [
            "grant.pre_assign",
            "yes",
            "nothing — veto only",
            "`fail_closed`",
            "Veto a role or permission assignment (four-eyes workflows). Veto-only.",
          ],
        ],
      },
      {
        type: "p",
        text: "An allow-list entry ending in a dot is a **namespace prefix**, and it matches a field that starts with the entry and has at least one character after the dot. So `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`, `extra`, `external_id` and `evil.ext.department`. Everything else follows from that one rule: `token.pre_issue` cannot reach `iss`, `sub`, `aud`, `exp`, `scope` or any other standard claim, because none of them begins with `ext.` — a hook that can rewrite `sub` is a hook that can mint a token for anyone, and a correctly signed reply setting it is refused exactly as a forged one is.",
      },
      {
        type: "p",
        text: "**The asymmetry in the last column is the most instructive fact on this page.** `token.pre_issue` defaults to fail-open because its mutation is optional enrichment — an unreachable reactor costs you a claim, and degrading a feature is the right answer. The other four default to fail-closed because they can veto: a fraud check that times out has not passed, and an unreachable approver is not an approval. A registration that names several events inherits the **strictest** default among them, in either array order.",
      },
      {
        type: "note",
        text: "`login.post_auth` covers every interactive sign-in, not only password login: it fires on password authentication, on SAML ACS, on the OIDC callback and on usernameless passkey sign-in — in each case after the credentials verify and before any session or token is issued. MFA completion and the username-bound WebAuthn ceremony are not separate firings; both continue a login already gated at its first step. The federated and usernameless paths have no step-up branch, so a `require_mfa` answer there fails the sign-in rather than being silently dropped — see [CONTRACT §22.5](https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md).",
      },
      { type: "h", id: "modes", text: "Intercept and listen" },
      {
        type: "p",
        text: "A registration is `intercept` or `listen`. An interceptor sits in the operation: the server publishes the event to that reactor's queue, waits up to the declared timeout, and applies the validated reply. A listener is fire-and-forget observation — the server never waits and never reads a reply, so it cannot affect any outcome.",
      },
      {
        type: "warn",
        text: "**Listen registrations are refused today.** `POST` and `PUT` answer `503` for `mode: \"listen\"`, because no hook site fans out to listeners yet: the registration would receive nothing, and — being a listener — would produce no outcome in which you could notice. Register with `mode: \"intercept\"`, or create it with `enabled: false` until the fan-out ships.",
      },
      {
        type: "p",
        text: "All five events above are interceptable, so the registry's `interceptable` flag has no effect today. It is carried because a sixth event may be listen-only, and the rule is already fixed: a listener may subscribe to **every** registered event, including one the registry marks non-interceptable — precisely because it cannot influence it.",
      },
      { type: "h", id: "vs", text: "Reactor or webhook?" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["", "Webhook", "Intercepting Reactor"],
        rows: [
          ["Transport", "Outbound HTTPS POST to a URL you configure", "AMQP consume from a durable, server-declared queue"],
          [
            "Authenticity",
            "HMAC-SHA256 over `timestamp.body`, in a signed-timestamp header",
            "HMAC over the whole message, in **both** directions, replay-protected with a nonce and a freshness window",
          ],
          ["When it runs", "After the change is committed", "Inside the operation, before it commits"],
          [
            "Can it affect the operation?",
            "Never",
            "Allow, deny, or a mutation limited to the event's allow-list",
          ],
          [
            "What it hears",
            "The domain events a webhook can subscribe to — see [Webhooks](#/docs/webhooks)",
            "The five registry events above, and nothing else",
          ],
          [
            "If it is unreachable",
            "Retried, then dead-lettered; the operation already happened",
            "The registration's `failure_policy` decides — and for four of the five events the default is to refuse",
          ],
        ],
      },
      { type: "h", id: "wire", text: "On the wire" },
      {
        type: "p",
        text: "Both directions carry the same v2 signature: `HMAC-SHA256` with the tenant's HKDF-derived AMQP subkey over the canonical serialization, with `nonce` and `issued_at` **inside** the signed bytes and a ±300 s two-sided freshness window. A reply is an instruction to change a token or refuse a login, so an unsigned reply is not a weak reply — it is not a reply at all. The two shapes below are illustrative; [CONTRACT §22.3–§22.4](https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md) is normative.",
      },
      {
        type: "code",
        caption: "event — server → reactor",
        code: `{
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "event": "token.pre_issue",
  "correlation_id": "22222222-2222-2222-2222-222222222222",
  "payload": { "sub": "alice", "client_id": "portal" },
  "timeout_ms": 500,
  "key_version": 2,
  "nonce": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "issued_at": "2026-07-10T12:00:00Z",
  "hmac_signature": "…"
}`,
      },
      {
        type: "code",
        caption: "reply — reactor → server",
        code: `{
  "correlation_id": "22222222-2222-2222-2222-222222222222",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "event": "token.pre_issue",
  "decision": "mutate",
  "patch": { "ext.cost_center": "42", "ext.department": "eng" },
  "key_version": 2,
  "nonce": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "issued_at": "2026-07-10T12:00:00Z",
  "hmac_signature": "…"
}`,
      },
      {
        type: "p",
        text: "`payload` never carries a credential, a token or a signing key: a reactor is told what is being decided, not handed the means to act on it elsewhere. `correlation_id` is the single-use handle for one dispatch and must be echoed **in the reply body** — copying it only into the AMQP property produces a reply the server discards. `timeout_ms` is inside the signed body so it cannot be widened in transit; it is sent so an actor can shed load rather than answer into a closed window.",
      },
      {
        type: "list",
        items: [
          "The server validates in a fixed order — identity, freshness, signature, then semantics — so allow-list logic is never spent on bytes nobody authenticated.",
          "**One forbidden patch key rejects the whole patch**, including the fields that would have been fine. An SDK must not quietly filter a handler's patch down to the allowed subset: that leaves the author believing a field was set when it was dropped.",
          "**`allow` and `patch` are mutually exclusive** — a mutation must be `decision: \"mutate\"`. `require_mfa` rides on `allow`, on `login.post_auth` only.",
          "Every rejection is audited and resolves to the registration's failure policy. A rejected reply is not a softer failure than no reply at all.",
        ],
      },
      { type: "h", id: "budget", text: "Timeouts and the budget" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Setting", "Value"],
        rows: [
          ["`timeout_ms` default", "500 ms"],
          ["`timeout_ms` accepted range", "1 … 5 000 ms — `0` and anything larger is refused at registration"],
          ["Chain wall-clock ceiling", "5 000 ms"],
          ["Effective per-reactor budget", "`min(timeout_ms, 5000 − elapsed)`"],
          ["Per-tenant in-flight interceptions", "64 by default"],
        ],
      },
      {
        type: "p",
        text: "Interceptors for one event run sequentially in ascending `priority`, and a deny short-circuits the rest. The budget is wall-clock rather than a sum, and running out of it is **not** a way to skip a check: when the ceiling is exhausted the remaining reactors are not contacted and each of their failure policies is applied anyway, so an unreached fail-closed veto still denies. Back-pressure is immediate rather than queued — breaching the in-flight cap fails the interception at once and applies the policy, because queueing behind a concurrency bound just turns it into an unbounded latency bound.",
      },
      {
        type: "note",
        text: "A fail-open timeout produces `allow` **and** an audit record naming the reactor. That pair is the whole difference between “no reactor was configured” and “the reactor never answered”, so do not infer reactor health from the outcome alone — `GET /api/v1/reactors/{id}` reports `last_seen_at`, `recent_timeout_count` and `recent_veto_count` for exactly this reason.",
      },
      { type: "h", id: "hotpath", text: "Never on the check path" },
      {
        type: "warn",
        text: "`authz.check`, `authz.check_batch` and `token.introspect` are **not hookable**, and no SDK may present them as such: they are absent from the registry, a registration naming one is refused as an unknown event, and the dispatcher resolves an unregistered event to `allow` without contacting anything. The reason is arithmetic, not policy — a reactor round trip is milliseconds and the check path's budget is microseconds. An application that needs external input on an authorization decision writes a **deny grant**, which the engine evaluates in the hot path at hot-path cost.",
      },
      { type: "h", id: "handlers", text: "Binding handlers" },
      {
        type: "p",
        text: "A reactor registered for three events opens with a dispatch on the event name, and that dispatch is where the expensive defect lives: the catch-all arm that returns *allow* answers on behalf of code that never ran, defeating an operator's fail-closed setting from a file they never read. Every SDK that ships the runtime therefore also ships a declarative binder — one handler per event, composed into the single handler the runtime takes. A name outside the registry is refused **at bind time**, and an event with no handler **abstains**: no reply, and the failure policy decides.",
      },
      {
        type: "codegroup",
        caption: "declarative handler binding",
        tabs: [
          {
            label: "TypeScript",
            code: `import { REACTOR_EVENTS, reactorHandlers, reactorServe } from 'axiam-sdk/amqp';

await reactorServe(
  options,
  reactorHandlers({
    [REACTOR_EVENTS.TOKEN_PRE_ISSUE]: (event) => mutate({ 'ext.cost_center': '42' }),
    [REACTOR_EVENTS.LOGIN_POST_AUTH]: async (event) => deny('embargoed region'),
  }),
);`,
          },
          {
            label: "Python",
            code: `from axiam_sdk.amqp import LOGIN_POST_AUTH, TOKEN_PRE_ISSUE, ReactorRouter, reactor_serve

router = ReactorRouter()

@router.on(TOKEN_PRE_ISSUE)
def enrich_token(event):            # sync or async, both work
    return mutate({"ext.cost_center": "42"})

@router.on(LOGIN_POST_AUTH)
async def screen_login(event):
    return deny("embargoed region") if await embargoed(event) else allow()

await reactor_serve(dialer, config, router.handler())`,
          },
          {
            label: "Go",
            code: `handler, err := amqp.NewReactorMux().
    On(amqp.ReactorEventTokenPreIssue, enrichToken).
    On(amqp.ReactorEventLoginPostAuth, screenLogin).
    Handler()
if err != nil {
    return err // every rejected binding at once, not one per run
}
err = amqp.ReactorServe(ctx, dialer, cfg, handler)`,
          },
          {
            label: "Swift",
            code: `// The §8b guard is a public, tested function — call it before
// anything opens a socket.
let endpoint = try amqpsEndpoint(brokerURL, caPEM: caPEM)

var router = ReactorRouter()
try router.on(.loginPostAuth) { event in
    let payload = try event.decodePayload(LoginPayload.self)
    return suspicious(payload) ? .allowWithStepUp : .allow
}

let config = ReactorConfig(tenantID: tenantID, reactorID: reactorID, signingKey: subkey)
try await reactorServe(config: config, transport: yourTransport, handler: router.handler())`,
          },
        ],
      },
      {
        type: "p",
        text: "The eight managed runtimes — Rust, TypeScript, Python, Java, Kotlin, C#, PHP and Go — bundle the AMQP client and connect for you. **Swift, C and C++ ship the protocol core over a transport you supply**: the same verification, canonical signing, allow-lists and binder, with no vendored broker client, because there is no maintained AMQP client for those targets this project is willing to put onto embedded and mobile deployments. Their transport interface has exactly two capabilities — take the next delivery, publish a reply to a named destination — and deliberately no declare, bind or queue-name derivation, since a reactor that can bind can bind itself to another tenant's issuance events.",
      },
      {
        type: "note",
        text: "Because that runtime never sees a broker URL, each of the three exposes the transport guard — `amqps://` only, no loopback exception, no plaintext fallback, no verification-skip switch — as a public, tested function (`amqpsEndpoint`, `axiam_amqps_endpoint`, `axiam::amqps_endpoint`) and calls it in its own example transport. A requirement that reads as enforced and is not is the failure mode that rule exists to stop.",
      },
      { type: "h", id: "registering", text: "Registering one" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/reactors", summary: "List registered Reactors, with health counters." },
          { method: "POST", path: "/api/v1/reactors", summary: "Register one. `400` on an unknown event or an out-of-range timeout." },
          { method: "GET", path: "/api/v1/reactors/{id}", summary: "Read one, including `last_seen_at` and the 24-hour timeout and veto counts." },
          { method: "PUT", path: "/api/v1/reactors/{id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/reactors/{id}", summary: "Remove it — never refused, so a bad registration can always be undone." },
          { method: "GET", path: "/api/v1/reactors/events", summary: "The event registry, verbatim — the live copy of the table above." },
        ],
      },
      {
        type: "code",
        caption: "POST /api/v1/reactors",
        code: `{
  "name": "fraud-screen",
  "description": "Denies logins from embargoed regions",
  "events": ["login.post_auth"],
  "mode": "intercept",
  "priority": 10,
  "timeout_ms": 500,
  "enabled": true
}`,
      },
      {
        type: "p",
        text: "Omit `timeout_ms` to take the 500 ms default, and omit `failure_policy` to take the strictest default among the events named. Every endpoint is permission-gated (`reactors:list`, `reactors:create`, `reactors:get`, `reactors:update`, `reactors:delete`), and the server declares the exchange, the queue and the bindings — an actor consumes, and never declares topology of its own.",
      },
      {
        type: "note",
        text: "The wire protocol — message shape, signing, the reply schema and the timeout semantics — is normative in [CONTRACT.md §22](https://github.com/ilpanich/axiam/blob/main/sdks/CONTRACT.md). The admin console's Reactors page is the same surface with a form on top.",
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
