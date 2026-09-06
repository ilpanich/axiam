import { API_INDEX, API_OPERATION_COUNT, API_PATH_COUNT, API_VERSION } from "../apiIndex";
import { contractLink } from "../contractAnchors";
import type { DocBlock, DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

const GH_BLOB = "https://github.com/ilpanich/axiam/blob/main";

/**
 * The endpoint index, expanded from the generated `apiIndex.ts`.
 *
 * The REST page used to show a dozen routes out of 177, picked by whoever last
 * edited it. These blocks are derived from the OpenAPI document instead, so the
 * page lists what the server actually serves and cannot fall behind it.
 */
const API_INDEX_BLOCKS: DocBlock[] = API_INDEX.flatMap((group) => [
  { type: "h", id: group.id, text: group.label },
  { type: "p", text: group.blurb },
  { type: "api", endpoints: group.operations },
]);

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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
        type: "p",
        text: "The running server serves the document and a browsable Swagger UI itself, at `/api/docs/openapi.json` and `/api/docs/`. Treat that as the authoritative copy for the build you are talking to — the committed spec is the same document, exported.",
      },
      {
        type: "p",
        text: "The document carries its own content digest at `info.x-axiam-spec-digest` — a SHA-256 over the document with the digest field itself removed, so it is a fixed point rather than a chicken-and-egg. `scripts/check-spec-digest.py` verifies it on every commit. It exists for the tooling around the SDKs: a generator deciding whether to re-run, a contract test asserting a vendored copy is current, a gateway keyed on a spec revision. Comparing digests is exact where comparing versions was not — an amendment that changes an operation without bumping `info.version` moves the digest.",
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
          "**CSRF applies to the credential the browser attaches by itself.** A request authenticated *only* by a bearer token needs no CSRF token: a cross-site page cannot set an `Authorization` header on a victim's behalf, so the requirement would be unsatisfiable rather than protective. A request carrying a bearer header **and** a session cookie is still checked, deliberately — that is precisely the shape where the browser supplies the cookie and an attacker supplies the header, so the exemption cannot itself become the bypass.",
          "**Tenancy is explicit.** Entity routes are tenant-scoped through the authenticated principal; OAuth2 endpoints take `tenant_id` as a query parameter. Nothing is inferred from a default.",
          "**Every route is permission-guarded.** A caller needs an explicit grant for the action behind the route — the same 115-permission registry the admin console uses.",
          "**Collections paginate** with `offset` and `limit`, and return the items plus a total.",
          "**Collections search** with `?search=`, on all twenty list endpoints. Each matches its own identifying columns plus the record's id, so a UUID copied out of a log line goes in the same box as a name. It is a substring match rather than tokenised full-text search, precisely so that pasting a fragment of an id finds the row. The filter applies to the `total` as well as to the page — a total describing the unfiltered set would hand the pager page numbers the filtered set cannot fill.",
          "**Mutations are audited.** Every write lands in the append-only audit log with the acting principal.",
        ],
      },
      { type: "h", id: "acting-tenant", text: "Acting on another tenant" },
      {
        type: "p",
        text: "An organization-level principal switches the tenant a request acts on with the `X-Axiam-Tenant` header, without signing in again. The header is honoured only for a principal that lives in the organization's reserved scope, and only for a tenant inside its own organization; anything else is a `403` rather than a silent fallback. See [Organization-level principals](#/docs/organization-scope).",
      },
      {
        type: "p",
        text: "One rule governs the interaction with self-service routes, and it is the one that bites: **a request about the caller's own record resolves in the tenant the caller lives in, whatever the header says.** That covers `/auth/me`, `/auth/password/change`, `GET` and `PUT /users/{id}` for the caller's own id, that user's MFA methods and `reset-mfa`, MFA enrolment and confirmation, WebAuthn registration, `/users/me/resend-verification`, the GDPR self-service requests and `/oauth2/userinfo`. Anybody else's id follows the header, as does everything that is not about a user at all.",
      },
      {
        type: "warn",
        text: "The acting-tenant header is `X-Axiam-Tenant`. Contract versions before 1.36 named it `X-Tenant-ID`, which the server does not read — a client following that letter switched nothing and received a perfectly successful response describing its own tenant's data. `X-Tenant-ID` still exists as the unconditional constructor-tenant header and is deliberately *not* renamed: renaming it would make it override the acting tenant on every request made after a switch.",
      },
      { type: "h", id: "example", text: "A worked example" },
      {
        type: "code",
        caption: "create a user, put them in a group, check access",
        code: "# A machine client gets a bearer token from the OAuth2 token endpoint.\n# (An interactive login sets cookies instead — see the Quickstart.)\nTOKEN=$(curl -sS -X POST 'https://iam.acme.dev/oauth2/token?tenant_id=<uuid>' \\\n  -d grant_type=client_credentials \\\n  -d client_id=\"$SA_CLIENT_ID\" -d client_secret=\"$SA_CLIENT_SECRET\" \\\n  | jq -r .access_token)\n\nUSER=$(curl -sS -X POST https://iam.acme.dev/api/v1/users \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"email\":\"dana@acme.dev\",\"username\":\"dana\"}' | jq -r .id)\n\ncurl -sS -X POST \"https://iam.acme.dev/api/v1/groups/$GROUP/members\" \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d \"{\\\"user_id\\\":\\\"$USER\\\"}\"\n\ncurl -sS -X POST https://iam.acme.dev/api/v1/authz/check \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"action\":\"read\",\"resource_id\":\"doc:1\"}'",
      },
      { type: "h", id: "index", text: "Every endpoint" },
      {
        type: "p",
        text: `**${API_OPERATION_COUNT} operations across ${API_PATH_COUNT} paths**, grouped by domain and in path order. This index is generated from \`sdks/openapi.json\` at \`${API_VERSION}\` — it is not a curated selection, so a route that exists appears here, and one that appears here exists. Endpoints marked \`PUBLIC\` are reachable **without an access token**; everything else needs one, and a permission behind it. Read that marker precisely on the OAuth2 endpoints: \`/oauth2/token\`, \`/oauth2/par\`, \`/oauth2/introspect\` and \`/oauth2/revoke\` take no bearer token, but they do authenticate the *client* — by secret, assertion or the TLS connection — so “no access token” is not “open”.`,
      },
      {
        type: "note",
        text: "Where a row carries no description, the handler has none in the specification beyond its route — the OpenAPI document is the place to fix that, not this page. For request and response schemas, read the document itself or point a viewer at the running server.",
      },
      ...API_INDEX_BLOCKS,
      { type: "h", id: "management", text: "Managing AXIAM from an SDK" },
      {
        type: "p",
        text: "Everything in the index above is reachable from any of the eleven SDKs as ordinary library code, not as hand-rolled HTTP. CONTRACT §27 defines that management surface, and it is generated rather than written: `sdks/management-registry.json` — the third artifact the SDKs vendor alongside `openapi.json` and the contract — classifies every operation in the spec into **24 namespaces** and names the **155** that make up the surface, and each SDK ships a generator over it plus a CI job that regenerates and diffs. So a new endpoint reaches every SDK by regeneration, and an SDK that has not regenerated fails its own build rather than quietly lagging.",
      },
      {
        type: "p",
        text: "The registry is explicit about what it leaves out, and why: the authentication endpoints (§1, §23, §25), the authorization checks (§1), the OAuth2 grants and relying-party helpers (§12, §14, §15, §26), UMA (§20), the WebAuthn ceremonies (§24) and the device-grant user-interaction endpoints (§14) are all protocol surfaces with their own hand-written contract sections. Management is the CRUD half, and only the CRUD half.",
      },
      {
        type: "list",
        items: [
          "**Namespaced, not flat.** Operations hang off a namespace handle — `client.service_accounts().rotate_secret(id)` — with a `client.management()` accessor beside it rather than instead of it. C is the one exception: it has no handle to hang operations on, so it gets the flat-symbol form.",
          "**`search` is applied server-side, before `offset` and `limit`.** On all twenty paginated operations. Filtering a page client-side is forbidden by the contract, because it silently changes what pagination means: page 2 of a filtered set is not the filtered part of page 2.",
          "**Sparse update or full replacement is classified per operation**, not guessed. A `PUT` that replaces and a `PATCH`-shaped `PUT` that merges are different things to a caller who omits a field, and the registry records which each one is.",
          "**Declarative management is the second half.** §27.6 defines a manifest form — describe the desired state, apply it — which the SDKs expose in whatever their language calls idiomatic.",
        ],
      },
      {
        type: "links",
        links: [
          {
            label: "CONTRACT §27 — Management API",
            href: contractLink("27"),
            note: "The normative section: namespaces, per-language naming, the pagination and search semantics, and how an SDK builds its generator.",
          },
          {
            label: "`sdks/management-registry.json`",
            href: `${GH_BLOB}/sdks/management-registry.json`,
            note: "The registry itself — every namespace, every operation, and the exclusions with their stated reasons.",
          },
        ],
      },
      { type: "h", id: "gdpr", text: "GDPR endpoints" },
      {
        type: "p",
        text: "The four data-subject endpoints are in the index above, under *Data-subject rights*. Export and erasure act on the caller's own account, or on another's with `users:erase`. The cancel link is the odd one: it arrives by email as a single-use token, so it is a `GET` with the token in the query and is reachable without a session — the person cancelling an erasure may already have lost access to the account they are rescuing.",
      },
      {
        type: "note",
        text: "Erasure pseudonymises the actor identity in the audit trail rather than deleting the records — an append-only log cannot have rows removed from it. The HMAC pepper that makes pseudonyms consistent is `AXIAM__GDPR_PSEUDONYM_PEPPER`; changing it breaks the linkage between old and new pseudonyms. See [Standards & compliance](#/docs/compliance).",
      },
      {
        type: "p",
        text: "An administrator's `DELETE /api/v1/users/{id}` is not the same operation, and the difference is worth knowing before you pick one. Deletion now **erases** the personal data rather than hiding it: `username`, `email` and `metadata` are overwritten with values derived from the row's own id, and the WebAuthn credentials, federation identity links and password history that live outside the user row go with them — the same tables the Art. 17 purge clears, so an administrator's delete and a data subject's request do not leave different residue.",
      },
      {
        type: "p",
        text: "Overwriting rather than tombstoning is what **frees the identifiers**. The username and email uniqueness indexes are enforced by the database, so a hidden tombstone would refuse the same person a new account later — and the duplicate-account error would itself disclose that the deleted account had existed. The row survives holding its id and nothing identifying, because audit entries name their actor by id and dropping it would leave every entry the user produced pointing at nothing.",
      },
      {
        type: "note",
        text: "What administrator deletion does **not** do, and why it is not a substitute for `POST /api/v1/account/delete`: it does not pseudonymise the audit log's actor references, and it writes no erasure proof. Where you need an Art. 17 record, use the data-subject pipeline.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "why", text: "Why gRPC" },
      {
        type: "p",
        text: "REST is the general-purpose surface; gRPC exists for the hot path. Inside a service mesh, sidecars and backends make authorization checks on nearly every request, and connection reuse plus binary framing is what keeps tail latency down. In the benchmark run, a single gRPC `CheckAccess` held a p99 of 90 ms at database saturation, and TLS 1.3 cost nothing measurable against plaintext.",
      },
      { type: "h", id: "services", text: "Services and RPCs" },
      {
        type: "p",
        text: "Five services, defined in `proto/axiam/v1/` and all registered by the same listener. Every request message is tenant-scoped — `tenant_id` is a field on the request, not a header, because there is no default tenant.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Service", "RPC", "What it does"],
        rows: [
          [
            "AuthorizationService",
            "`CheckAccess`",
            "One access check. The hot-path RPC this service exists for.",
          ],
          [
            "AuthorizationService",
            "`BatchCheckAccess`",
            "Several checks in one round trip; results preserve input order.",
          ],
          ["TokenService", "`ValidateToken`", "Signature, expiry and tenant. Returns `cnf` and `token_type`."],
          [
            "TokenService",
            "`IntrospectToken`",
            "Full RFC 7662 claims, plus `scope`, `client_id`, UMA `permissions` and `ext_exchange_iss`.",
          ],
          ["UserInfoService", "`GetUserInfo`", "The OIDC identity read — the gRPC-only counterpart of REST's userinfo endpoint (§1.1)."],
          ["UserService", "`GetUser`", "Lookup by id."],
          [
            "UserService",
            "`ValidateCredentials`",
            "A username/password check that issues no token. An Argon2id verification, and rate-limited as a CPU guard rather than a read ceiling.",
          ],
          [
            "ReactorAdminService",
            "`ListReactorEvents`, `CreateReactor`, `ListReactors`, `GetReactor`, `UpdateReactor`, `DeleteReactor`",
            "Reactor registration and lifecycle — the administrative surface behind the [reactors page](#/docs/reactors).",
          ],
        ],
      },
      {
        type: "note",
        text: "**Rate limits follow the family, not the service name.** `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` sizes the authorization and token services; `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` sizes `UserService` **and, since the beta11 remediation, the whole of `ReactorAdminService`** — which used to fall through to the authorization family's much larger ceiling. It defaults to **10/s per IP and deliberately does not move with the deployment posture**, because an administrative surface has no throughput case: reactor CRUD over gRPC above that rate needs the variable raised explicitly. See [Sizing your rate limits](https://github.com/ilpanich/axiam/blob/main/docs/deployment/rate-limit-sizing.md).",
      },
      { type: "h", id: "checkaccess", text: "One CheckAccess call" },
      {
        type: "p",
        text: "The request names the tenant, the subject, an action and a resource. `subject_id` may be left empty to mean *the subject carried by the verified token* — over gRPC it can only ever restate the caller, since there is no cross-subject form of the check on this transport.",
      },
      {
        type: "codegroup",
        caption: "CheckAccess",
        tabs: [
          {
            label: "Rust",
            code: 'use axiam_sdk::grpc::{AuthzGrpcClient, CheckAccessRequest, GrpcChannelConfig, build_channel};\n\n// `connect_lazy` performs no network I/O — the TCP and TLS handshake\n// happens on the first RPC.\nlet channel = build_channel("https://iam.acme.dev:50051", &GrpcChannelConfig::default())?;\nlet client = AuthzGrpcClient::new(channel, token_manager, refresh_fn);\n\nlet decision = client\n    .check_access(CheckAccessRequest {\n        tenant_id,\n        subject_id,\n        action: "resource:read".to_string(),\n        resource_id,\n        scope: None,\n    })\n    .await?;\n\nprintln!("allowed: {}, reason: {:?}", decision.allowed, decision.reason);',
          },
          {
            label: "Go",
            code: '// arg 1 is an optional custom CA PEM for a dev server (§6).\ncreds, err := axiamgrpc.NewTLSCredentials(nil, nil, nil)\nconn, err := axiamgrpc.NewGRPCClient(target, creds, interceptor)\nauthzClient := axiamgrpc.NewAuthzClient(conn, refreshFn)\n\nallowed, denyReason, err := authzClient.CheckAccess(ctx, axiamgrpc.CheckAccessRequest{\n\tTenantID:   tenantID,\n\tSubjectID:  subjectID,\n\tAction:     "resource:read",\n\tResourceID: resourceID,\n})',
          },
          {
            label: "Python",
            code: 'from axiam_sdk.grpc import AuthzGrpcClient\n\nclient = AuthzGrpcClient(\n    "iam.acme.dev:50051",\n    token_fn=lambda: current_access_token,  # non-blocking cache read\n    tenant_id=tenant_id,\n    refresh_fn=refresh_fn,  # invoked once on UNAUTHENTICATED, then one retry\n)\n\ndecision = client.check_access(subject_id, "resource:read", resource_id)',
          },
          {
            label: "grpcurl",
            code: '# The server registers no reflection service, so point grpcurl at the\n# protos directly.\ngrpcurl \\\n  -import-path proto -proto axiam/v1/authorization.proto \\\n  -H "authorization: Bearer $ACCESS_TOKEN" \\\n  -d \'{"tenant_id":"<uuid>","action":"resource:read","resource_id":"<uuid>"}\' \\\n  iam.acme.dev:50051 axiam.v1.AuthorizationService/CheckAccess',
          },
        ],
      },
      {
        type: "p",
        text: "The response carries `allowed` plus a machine-readable `reason_code`: `allowed`, `no_grant` when nothing matched, or `denied_by_rule` when an explicit deny overrode an allow. The distinction is the one worth surfacing to a user — `no_grant` means ask an administrator, `denied_by_rule` means one has already decided.",
      },
      {
        type: "warn",
        text: "`deny_reason` is deprecated. It carries the same string as `reason` until AXIAM 2.0 removes it; new code reads `reason` and must not depend on the older field surviving.",
      },
      { type: "h", id: "deadlines", text: "Deadlines and retries" },
      {
        type: "p",
        text: "The retry policy is contract-level and identical across transports, so a gRPC check retries exactly as a REST one does. Every value below is binding on an SDK claiming conformance.",
      },
      {
        type: "table",
        headers: ["Parameter", "Value"],
        rows: [
          ["Attempt cap", "3 total — one initial call and two retries"],
          ["Base delay", "200 ms"],
          ["Delay cap", "5 s on any single wait"],
          ["Backoff", "`min(cap, base × 2^(attempt−1))` — 200 ms, then 400 ms"],
          ["`Retry-After`", "A floor on the computed backoff, never a ceiling"],
        ],
      },
      {
        type: "p",
        text: "Only side-effect-free operations are eligible, and that is not the same as *reads a GET*: `CheckAccess` and `BatchCheckAccess` both qualify, and they are the reason the policy exists. Token minting, credential validation and every mutation are excluded — a transient failure after the server committed is indistinguishable at the client from one before it committed.",
      },
      {
        type: "note",
        text: "A caller who needs more than three attempts should retry at their own layer, where the deadline is known. An SDK may lower the cap or switch retry off; it may never raise it, because a caller who can raise it turns one client into the herd a backoff exists to prevent.",
      },
      { type: "h", id: "sender-constrained", text: "Sender-constrained tokens" },
      {
        type: "note",
        text: "`ValidateToken` and `IntrospectToken` return a `cnf` claim, and a token that carries one is **not** a bearer token whichever wire it arrived on. `valid: true` means the signature, expiry and tenant check out — not that the token is usable as presented. When `cnf` is present the caller must verify possession against its **own** connection, because AXIAM cannot: the proof is bound to the caller's connection, not to the one carrying the introspection call. A `cnf` whose members are all empty must be refused rather than read as unbound — proto3 cannot tell an absent string from an empty one.",
      },
      {
        type: "p",
        text: "AXIAM's own gRPC interceptor refuses `jkt`-bound tokens, because a Tonic interceptor sees neither the HTTP method nor the URI a DPoP proof is bound to. That is the server's limitation and should not be copied: an SDK guarding a real endpoint knows both, so it can and should verify the proof.",
      },
      { type: "h", id: "publishing", text: "Publishing gRPC outside the mesh" },
      {
        type: "p",
        text: "The listener binds loopback in Compose and ClusterIP in Kubernetes. That is a default rather than a prohibition — it may be published, but only through the same edge as REST, on 443, path-matched, and as an allowlist of the services you actually want reachable. A bare port-forward is not a supported shape: without a proxy appending the real peer, a client keys its own rate-limit bucket and no setting repairs it. [Production hardening](#/docs/hardening#grpc) has the rule, the `AXIAM__GRPC__STRICT_REVOCATION` recommendation and the certificate-reload caveat.",
      },
      { type: "h", id: "codegen", text: "Generating your own stubs" },
      {
        type: "p",
        text: "Integrating from a language with no published AXIAM SDK? Generate stubs straight from the `.proto` files with `buf generate`, or `protoc` plus your language's gRPC plugin. They are self-contained proto3 with no imports beyond the well-known types, and CI runs `buf lint` and `buf breaking` on every change — so the contract is guarded against accidental breakage.",
      },
      { type: "code", code: "buf generate   # from the vendored proto/ tree" },
      {
        type: "note",
        text: "The Kotlin, Swift, C and C++ SDKs cover the REST surface. gRPC is deferred rather than scheduled for them — the contract sets no §-level gRPC requirement for those four — so use the REST transport, or generate stubs straight from `proto/` if you need this surface. The one thing REST cannot substitute for is `GetUserInfo`, which has no REST form in the SDK vocabulary.",
      },
      {
        type: "links",
        links: [
          {
            label: "gRPC API reference",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/api/grpc.md",
            note: "The service definitions, the metadata each RPC expects, and the error mapping.",
          },
        ],
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "why", text: "What runs over the bus" },
      {
        type: "p",
        text: "Some work should not happen on a request thread. Audit ingestion must not slow down the operation being audited; webhook delivery must survive a receiver being down; a mail send must not fail a signup. AXIAM puts all of it on RabbitMQ, and exposes the same authorization engine there for callers that want a decision without holding a connection open.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Queue", "Purpose", "Dead-letters to"],
        rows: [
          ["axiam.authz.request", "Deferred authorization requests.", "`axiam.authz.request.dlq`"],
          ["axiam.authz.response", "The decisions, correlated back to the requester.", "—"],
          ["axiam.audit.events", "Audit ingestion, off the request hot path.", "`axiam.audit.events.dlq`"],
          ["axiam.notifications", "Notification-rule delivery.", "—"],
          ["axiam.mail.outbound", "Outbound mail — verification, reset, alerts.", "`axiam.mail.outbound.dlq`"],
          ["axiam.webhook", "Webhook delivery.", "`axiam.webhook.dlq`"],
          [
            "axiam.webhook.retry",
            "Delay queue for webhook backoff. Nothing consumes it — a message published here with a per-message TTL dead-letters back to `axiam.webhook` when the TTL expires, which is how the retry delay happens without a consumer sleeping.",
            "`axiam.webhook` (by design)",
          ],
        ],
      },
      {
        type: "note",
        text: "Dead-lettering is per queue, not universal. Four queues have a DLQ; `axiam.authz.response` and `axiam.notifications` do not, and `axiam.webhook.retry` dead-letters *forward* into the primary queue as its delay mechanism rather than as a failure path. Messages that reach a `.dlq` are real and replayable — they are not dropped.",
      },
      { type: "h", id: "exchanges", text: "Exchanges" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Exchange", "Kind", "Purpose"],
        rows: [
          [
            "axiam.authz.cache.invalidate",
            "fanout",
            "Cross-replica authorization decision-cache invalidations. Fanout rather than a work queue for a load-bearing reason: every replica binds its own exclusive auto-delete queue, so every replica sees every invalidation. A shared queue would hand each message to exactly one consumer and leave the rest serving stale allows.",
          ],
          [
            "axiam.reactor.events",
            "reactor hook events",
            "The Reactor bus — see [Reactors](#/docs/reactors) for the request/reply contract.",
          ],
        ],
      },
      { type: "h", id: "envelope", text: "One signed message" },
      {
        type: "p",
        text: "Every message carries an HMAC-SHA256 over its own body, and since `key_version` 2 that body must also carry a `nonce` and an `issued_at`. Both are always emitted — never omitted — so they fall inside the signed bytes.",
      },
      {
        type: "code",
        caption: "an authz request as it travels · the reference vector",
        code: '{\n  "correlation_id": "22222222-2222-2222-2222-222222222222",\n  "tenant_id":      "11111111-1111-1111-1111-111111111111",\n  "subject_id":     "33333333-3333-3333-3333-333333333333",\n  "action":         "documents:read",\n  "resource_id":    "44444444-4444-4444-4444-444444444444",\n  "scope":          "confidential",\n  "key_version":    2,\n  "nonce":          "55555555-5555-5555-5555-555555555555",\n  "issued_at":      "2026-07-10T12:00:00Z",\n  "hmac_signature": "13d73b3aa8a400fc3f64dbc20b36952d8584142feb822b5f77495b0f587049ed"\n}',
      },
      {
        type: "p",
        text: "The signature is computed over the same object with `hmac_signature` **absent**, serialized in exactly the field order above — `correlation_id`, `tenant_id`, `subject_id`, `action`, `resource_id`, `scope` (omitted when null), `key_version`, `nonce`, `issued_at`. Order is part of the construction, not a formatting detail: a verifier that re-serializes in a different order computes a different digest and rejects a valid message.",
      },
      {
        type: "p",
        text: "The key is not the master secret. It is a per-tenant subkey derived with HKDF-SHA256, domain-separated and versioned by `key_version`, then scoped to the tenant — so a signature made with one tenant's subkey never verifies under another's, and rotating the master key yields entirely different subkeys without breaking messages already in flight under the previous version.",
      },
      {
        type: "table",
        headers: ["Check", "Rule"],
        rows: [
          ["Signature", "Recompute and compare in constant time. A mismatch is nacked **without** requeue and logged as a security event — never the digest itself."],
          ["Version", "`key_version` below 2 is rejected outright. The v2 cutover is hard; there is no grace path."],
          ["Freshness", "`issued_at` must lie within ±5 minutes of the consumer's clock (`AXIAM__AMQP__REPLAY_SKEW_SECS`)."],
          ["Replay", "`(tenant_id, nonce)` is recorded durably; a repeat inside the freshness window is a replay and is rejected."],
        ],
      },
      {
        type: "note",
        text: "Vectors every SDK must reproduce byte-for-byte live in `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json` — the sample above is one of them. Reproducing the canonical JSON and recomputing the digest is the conformance test, which is why the fixture is shared rather than each SDK inventing its own.",
      },
      { type: "h", id: "security", text: "Transport security" },
      {
        type: "warn",
        text: "AMQP is **TLS-only**. `AXIAM__AMQP__URL` must be `amqps://`; every other scheme is refused before a socket opens, in a debug build exactly as in a release one. There is no environment variable, build profile or flag that changes the answer — the `ALLOW_PLAINTEXT` escape hatch that once permitted `amqp://` has been removed.",
      },
      {
        type: "p",
        text: "That removal has a history worth repeating, because it is the usual shape of this failure. The flag existed for a year, and four of the project's own stacks reached for it — dev compose, the e2e stack, the benchmark target and CI — each with a locally sound argument. None was wrong on its own. The aggregate was that \"AMQP is TLS-only\" described the production compose file and the Kubernetes manifests, and nothing else the repository actually ran.",
      },
      {
        type: "p",
        text: "An in-cluster broker's certificate is usually privately issued, so **supplying a custom CA bundle is the common case, not the exception** — every SDK that speaks AMQP must support it. Client certificates toward the broker are supported where an SDK offers them, and the certificate and key are required together: half a client identity fails closed rather than connecting without the mutual half.",
      },
      {
        type: "note",
        text: "TLS and the HMAC are not alternatives. TLS gives confidentiality but terminates at the broker, which then re-sends; the HMAC gives authenticity and replay protection end-to-end **across** that hop. Production needs both, and an SDK offering either as a substitute for the other is not conformant.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "tokens", text: "Minting a provisioning token" },
      {
        type: "p",
        text: "A SCIM client authenticates with a **provisioning token** — a long-lived, revocable bearer handle meant to be pasted into an IdP once and forgotten. It is not an access token, and it is not a separate token *type* on the SCIM endpoints: `/scim/v2/*` uses the same bearer authentication as the rest of the REST API.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Create a dedicated provisioning user",
            body: "Non-interactive, used for nothing else. A shared administrator account here makes the audit trail useless and the blast radius unnecessary.",
            code: 'POST /api/v1/users\n{ "username": "scim-provisioner", "...": "..." }',
          },
          {
            title: "Create a role holding only scim:provision",
            body: "Least privilege, and specifically not the `admin` role — the default-role seeder grants admin every permission except `admin:bootstrap`, so it carries `scim:provision` along with everything else.",
            code: 'POST /api/v1/roles\nPOST /api/v1/roles/{role_id}/permissions   { "permission": "scim:provision" }',
          },
          {
            title: "Assign the role to that user",
            body: "The token you mint next inherits its authority from here, so this is the step that decides what the IdP can do.",
            code: "POST /api/v1/roles/{role_id}/users",
          },
          {
            title: "Mint the provisioning token",
            body: "Requires `scim_tokens:create`. The value is returned exactly once and stored only as a SHA-256 hash — there is no way to read it back.",
            code: "POST /api/v1/scim-tokens",
          },
          {
            title: "Paste it into the IdP",
            body: "Okta calls this HTTP Header authentication; Entra calls it the Secret Token. Nothing else needs to be configured on the AXIAM side.",
          },
        ],
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/scim-tokens", summary: "List provisioning tokens for the tenant." },
          { method: "POST", path: "/api/v1/scim-tokens", summary: "Mint one. The value is returned exactly once." },
          { method: "DELETE", path: "/api/v1/scim-tokens/{id}", summary: "Revoke one." },
        ],
      },
      { type: "h", id: "token-limits", text: "What the token can and cannot do" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Property", "Behaviour"],
        rows: [
          [
            "Scope",
            "Accepted on `/scim/v2/*` and **nowhere else** — not `/api/v1/*`, not `/oauth2/*`. That containment is what makes a year-long credential defensible in a system whose access tokens live 15 minutes.",
          ],
          [
            "Permissions",
            "**None of its own.** It authenticates *as* the tenant user it was minted for, and that user's `scim:provision` grant decides everything. Unassign the role or deactivate the user and every token bound to them stops working — no separate revocation needed.",
          ],
          ["Storage", "Only a SHA-256 hash is kept. The value is shown once, at creation."],
          [
            "Recognisability",
            "Fixed prefix `axiam_scim_`, so a secret scanner or a grep finds it if it is ever pasted somewhere it should not be.",
          ],
          [
            "Lifetime",
            "Always expires — there is no never-expires option. The ceiling is `AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS`, default 365.",
          ],
          [
            "Tenant reach",
            "One tenant, enforced by construction rather than by a check: every repository call takes its tenant id from the token's own claim, never from the request path or body. A token for tenant A cannot even name tenant B's users in a query.",
          ],
        ],
      },
      {
        type: "warn",
        text: "**Treat this as an administrator credential, not an integration credential.** RFC 7643 makes `password` a writable User attribute and `PATCH /scim/v2/Users/{id}` honours it — so a holder of `scim:provision` can set any user's password in the tenant, including a tenant administrator's, and then sign in as them. That makes the one permission strictly more powerful than `users:create` and `users:update` combined; the native admin API has no equivalent, because `PUT /api/v1/users/{id}` never writes a password hash. Rotate and store it the way you would an admin password.",
      },
      {
        type: "note",
        text: "Most Okta and Entra deployments federate and never push a password, so nothing is lost by the IdP never exercising that capability. AXIAM cannot yet take it away, though — `password` writes are not behind a second permission. Worth knowing before you grant it rather than after.",
      },
      { type: "h", id: "deprovision", text: "What deprovisioning actually does" },
      {
        type: "p",
        text: "Deactivation is immediate and complete. A SCIM `password` write, an `active: false` (by `PUT` or `PATCH`), and `DELETE /scim/v2/Users/{id}` each revoke every live session **and** every OAuth2 refresh token the target holds, on top of flushing the authorization decision cache.",
      },
      {
        type: "note",
        text: "That last part is the fix for a real gap: before it, only the decision cache was flushed, so an account an offboarding job had just deactivated still held a spendable refresh token. If you are reasoning about offboarding latency, this is the behaviour to rely on.",
      },
      {
        type: "warn",
        text: "Deactivation, not deletion, is usually what you want from an IdP. A SCIM `DELETE` removes the account; `active: false` disables sign-in while leaving the identity intact for the audit trail. Configure your IdP's deprovisioning action deliberately — both are wired, and they are not the same decision.",
      },
      { type: "h", id: "okta", text: "Okta" },
      {
        type: "steps",
        steps: [
          {
            title: "Create or edit an app integration with SCIM provisioning",
            body: "In the Okta Admin Console, under the app's Provisioning tab.",
          },
          {
            title: "Set the SCIM connector base URL",
            body: "The whole SCIM surface hangs off this prefix.",
            code: "https://<your-axiam-host>/scim/v2",
          },
          {
            title: "Set the unique identifier field to userName",
            body: "This is the attribute AXIAM filters on, and the only User filter supported besides `externalId`.",
          },
          {
            title: "Enable the provisioning actions you want",
            body: "Push New Users, Push Profile Updates and Push Groups are all supported — standard CRUD plus PATCH.",
          },
          {
            title: "Set authentication mode to HTTP Header and paste the token",
            body: "The provisioning token from the steps above. Okta's own Test API Credentials button then exercises the real request shapes: a filtered user lookup, a create, and a deactivating PATCH.",
          },
        ],
      },
      {
        type: "p",
        text: "Okta deactivates with `{\"op\": \"replace\", \"path\": \"active\", \"value\": false}`. Group push sends a `displayName` and, once members are assigned, a `members` array, then patches membership with a `members[value eq \"<uuid>\"]` remove when one user leaves the group.",
      },
      { type: "h", id: "entra", text: "Microsoft Entra ID" },
      {
        type: "steps",
        steps: [
          {
            title: "Set provisioning mode to Automatic",
            body: "Entra admin center → Enterprise applications → your app → Provisioning.",
          },
          {
            title: "Set the Tenant URL",
            body: "Entra's name for the same SCIM base URL.",
            code: "https://<your-axiam-host>/scim/v2",
          },
          {
            title: "Paste the provisioning token as the Secret Token",
            body: "Same credential as Okta's HTTP Header value.",
          },
          {
            title: "Test the connection",
            body: "Entra probes a single-user page as its validity check, so a green result means auth and paging both work.",
            code: "GET /scim/v2/Users?startIndex=1&count=1",
          },
          {
            title: "Leave the default attribute mappings alone",
            body: "Entra's defaults already match the supported subset: `userPrincipalName` to `userName`, `mail` and `otherMails` to `emails`, `givenName` and `surname` to the `name` sub-attributes, and `accountEnabled` to `active`.",
          },
        ],
      },
      {
        type: "note",
        text: "Entra deactivates with a path-less operation — `{\"op\": \"replace\", \"value\": {\"active\": false}}` — where Okta names the path. Both shapes are handled, which is the kind of divergence that otherwise shows up as an IdP that can create users but never disable them.",
      },
      { type: "h", id: "limits", text: "Rate limiting" },
      {
        type: "p",
        text: "The whole `/scim/v2` scope shares **one** bucket, `AXIAM__RATE_LIMIT__SCIM_PER_MIN`, defaulting to 600 per minute per IP — Users, Groups and discovery, reads and writes alike. Past it, requests get the standard `429` with `Retry-After: 60`, which a well-behaved SCIM client honours.",
      },
      {
        type: "note",
        text: "That ceiling is a CPU guard rather than a throughput number: creating a SCIM user generates and Argon2id-hashes an initial password, and a `password` patch re-hashes one. No rate-limit profile preset moves it — a service-mesh capacity decision must not silently widen an administrative surface. For scale, at a typical IdP page size of 200 a full import of a 100,000-user directory is roughly 500 list calls, well inside one minute's budget.",
      },
      {
        type: "links",
        links: [
          {
            label: "SCIM provisioning reference",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/api/scim-provisioning.md",
            note: "Field mappings, the PATCH shapes each IdP sends, and the contract fixtures.",
          },
        ],
      },
      {
        type: "note",
        text: "The Okta and Entra contract fixtures are hand-constructed from each vendor's published SCIM notes and RFC 7644's examples, not captured from live traffic. Read them as the request shapes those vendors are documented to send, rather than as a captured-traffic compatibility guarantee.",
      },
      {
        type: "cards",
        cards: [
          {
            title: "Federation (SAML & OIDC) →",
            body: "The other half: federation authenticates, provisioning creates. They are not substitutes.",
            to: "docs",
            doc: "federation",
          },
        ],
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
            label: "Rust",
            code: `use axiam_sdk::webhook::{WebhookVerifyOptions, verify_webhook};

async fn receive(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("");

    let opts = WebhookVerifyOptions::new()
        .event_type(header("X-Axiam-Event"))
        .delivery_id(header("X-Axiam-Delivery"))
        .timestamp_header(header("X-Axiam-Timestamp"));

    // \`body\` is the UNPARSED request body — verify first, parse after.
    match verify_webhook(&secret, header("X-Axiam-Signature"), &body, &opts) {
        Ok(event) => {
            if already_seen(event.delivery_id) {
                return HttpResponse::Ok().finish();   // at-least-once retry
            }
            handle(serde_json::from_slice(event.body).unwrap());
            HttpResponse::Ok().finish()
        }
        // Never echo the reason back to the sender.
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}`,
          },
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
            label: "Rust",
            code: `use axiam_sdk::amqp::reactor::{ReactorDecision, ReactorRouter, events, reactor_serve};

let handler = ReactorRouter::new()
    .bind(events::TOKEN_PRE_ISSUE, |event| async move {
        ReactorDecision::mutate([("ext.cost_center", "42")])
    })
    .bind(events::LOGIN_POST_AUTH, |event| async move {
        ReactorDecision::deny("embargoed region")
    })
    .build()?;   // every rejected binding at once, not one per run

reactor_serve(config, handler).await`,
          },
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
      {
        type: "links",
        links: [
          {
            label: "Reactors — the admin guide",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/admin/reactors.md",
            note: "Choosing hook events and a failure policy, the mutation allow-lists, and what a reactor may and may not change.",
          },
        ],
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
