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
            "`users`, `groups`, `roles`, `permissions`, `resources`, `service-accounts`, `oauth2-clients`, `organizations`, `tenants`, `certificates`, `pgp-keys`, `webhooks`, `reactors`, `notification-rules`, `federation-configs`, `scim-tokens`, `scim-targets`, `audit-logs`, `settings`.",
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
          "**Two ways to authenticate.** A machine client sends `Authorization: Bearer <access_token>`, obtained from the OAuth2 token endpoint — and which routes accept a machine's token is decided per route; see [Who may call which route](#/docs/rest#who-may-call). An interactive login sets `httpOnly` cookies instead — `POST /auth/login` returns no token in its body — and state-changing requests must then echo the `axiam_csrf` cookie in an `X-CSRF-Token` header. The SDKs handle the second case for you.",
          "**CSRF applies to the credential the browser attaches by itself.** A request authenticated *only* by a bearer token needs no CSRF token: a cross-site page cannot set an `Authorization` header on a victim's behalf, so the requirement would be unsatisfiable rather than protective. A request carrying a bearer header **and** a session cookie is still checked, deliberately — that is precisely the shape where the browser supplies the cookie and an attacker supplies the header, so the exemption cannot itself become the bypass.",
          "**Tenancy is explicit.** Entity routes are tenant-scoped through the authenticated principal; OAuth2 endpoints take `tenant_id` as a query parameter. Nothing is inferred from a default.",
          "**Every route is permission-guarded.** A caller needs an explicit grant for the action behind the route — the same 116-permission registry the admin console uses.",
          "**Collections paginate** with `offset` and `limit`, and return the items plus a total.",
          "**Collections search** with `?search=`, on all twenty-one list endpoints. Each matches its own identifying columns plus the record's id, so a UUID copied out of a log line goes in the same box as a name. It is a substring match rather than tokenised full-text search, precisely so that pasting a fragment of an id finds the row. The filter applies to the `total` as well as to the page — a total describing the unfiltered set would hand the pager page numbers the filtered set cannot fill.",
          "**Mutations are audited.** Every write lands in the append-only audit log with the acting principal.",
        ],
      },
      { type: "h", id: "who-may-call", text: "Who may call which route" },
      {
        type: "p",
        text: "Every guarded route takes an AXIAM access token, from the `axiam_access` cookie or an `Authorization: Bearer` header. Which **kind** of principal may hold it is the token's `aud` claim, and the OpenAPI document says it per operation, as a security scheme:",
      },
      {
        type: "table",
        headers: ["Security scheme in the spec", "Token", "Accepted on"],
        rows: [
          ["`bearer`", "a user's (`aud` = `axiam:user`)", "every guarded route"],
          [
            "`service_account`",
            "a service account's (`aud` = `axiam:m2m`, `sub_kind` = `service_account`), from client credentials or the mTLS device login",
            "only the operations that list it",
          ],
        ],
      },
      {
        type: "p",
        text: "An operation that lists both admits either. In `1.0.0-beta17` those are the eight **management families** — resources, scopes, permissions, roles (the assignment routes included), groups, service accounts, certificates (generate, sign-csr, bind, list, get, revoke) and webhooks — plus `POST /api/v1/authz/check` and `/api/v1/authz/check/batch`. Every other route is human-only and answers a service-account token with `401`: self-service (`/auth/me`, MFA, sessions, password change), users, organizations and tenants, settings, CA certificates, PGP keys, SCIM tokens, outbound SCIM targets, federation configuration, OAuth2 clients, reactors, audit logs, notification rules, email config and WebAuthn policy. Before `1.0.0-beta17` every management route took a user token only, so a service account could authenticate and then reach nothing but `/authz/check`.",
      },
      {
        type: "list",
        items: [
          "**Admitted is not allowed.** What a service account may do on an admitted route is decided by the roles assigned to it (`POST /api/v1/roles/{role_id}/service-accounts`), exactly as for a user. An account with no role gets `403` with `\"error\": \"authorization_denied\"` and the checked `action` in the body.",
          "**Tenant.** An account created in an ordinary tenant acts in that tenant only; `X-Axiam-Tenant` naming another is `403`. One created in the organization's reserved scope may name a tenant of its organization, within the tenants its assignments reach, as an organization administrator can.",
          "**Certificates.** A service account issues leaves under the signing CA of the tenant it acts on, never directly under the organization CA, wherever it lives.",
          "**Certificate-bound tokens.** A device token carries `cnf.x5t#S256` and is refused (`401`) unless presented over mTLS with that certificate.",
          "**Audit.** Its requests are recorded with actor type `service_account`, so the log tells a machine's write from a person's.",
          "**Revocation.** A machine token has no session. Disabling the account stops new tokens; one already issued lives out its access-token lifetime.",
        ],
      },
      {
        type: "note",
        text: "A machine-audience token whose `sub_kind` is not `service_account` — an OAuth2 client's, or a user's token narrowed to `axiam:m2m` by token exchange — is refused on these routes with `401`, on `/authz/check` too. The full rule set is in [the API guide](https://github.com/ilpanich/axiam/blob/main/docs/api/README.md#authentication--who-may-call-which-route); creating the account and assigning its roles is on [Service accounts](#/docs/service-accounts).",
      },
      { type: "h", id: "recent", text: "Endpoints added since 1.0.0-beta12" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/oauth2/userinfo", summary: "The OIDC claims, with the token in a header or (POST only) an access_token form field.", public: true },
          { method: "GET", path: "/oauth2/revocations", summary: "Hashed ids of sessions revoked within the last access-token lifetime. Optional, off by default, public by argument.", public: true },
          { method: "GET", path: "/api/v1/account/consents", summary: "The signed-in subject's own OIDC scope consents." },
          { method: "POST", path: "/api/v1/account/consents/oidc-scopes", summary: "Consent to a client and an exact scope set." },
          { method: "DELETE", path: "/api/v1/account/consents/oidc-scopes", summary: "Withdraw every OIDC scope consent." },
          { method: "DELETE", path: "/api/v1/account/consents/oidc-scopes/{client_id}", summary: "Withdraw it for one client." },
          { method: "GET", path: "/api/v1/users/{user_id}/sessions", summary: "A user's sessions with their refresh-replay counters." },
          { method: "POST", path: "/api/v1/certificates/sign-csr", summary: "Issue an end-entity certificate from a CSR you bring; no key is generated and none is returned.", },
          { method: "POST", path: "/api/v1/auth/webauthn/setup/register/start", summary: "Enrol a passkey or security key as the first factor during forced enrolment, from the login's setup token.", public: true },
          { method: "POST", path: "/api/v1/auth/webauthn/setup/register/finish", summary: "Complete it, and the interrupted login with it.", public: true },
          { method: "GET", path: "/.well-known/oauth-authorization-server", summary: "In `1.0.0-beta16`: the RFC 8414 alias of the OIDC discovery document — same handler, same body, same optional `?tenant_id=`.", public: true },
          { method: "GET", path: "/.well-known/oauth-authorization-server/t/{tenant_id}", summary: "Authorization-server metadata for one tenant, at the RFC 8414 §3.1 path-insertion form of the issuer `{root}/t/{tenant_id}`. Served with `AXIAM__AUTH__TENANT_ISSUER_PATHS=true`.", public: true },
          { method: "GET", path: "/.well-known/openid-configuration/t/{tenant_id}", summary: "The same tenant discovery document, at the OIDC Discovery path with the RFC 8414 §3.1 insertion applied.", public: true },
          { method: "GET", path: "/t/{tenant_id}/.well-known/openid-configuration", summary: "The same tenant discovery document, at the path OpenID Connect Discovery 1.0 §4 constructs by appending to the issuer.", public: true },
          { method: "POST", path: "/oauth2/register", summary: "In `1.0.0-beta16`: RFC 7591 dynamic client registration. Off by default on every tenant, in which case it answers `403` and discovery carries no `registration_endpoint`.", public: true },
          { method: "POST", path: "/api/v1/oauth2-clients/registration-tokens", summary: "Mint the single-use credential RFC 7591 §1.2's protected registration profile requires." },
          { method: "GET", path: "/api/v1/oauth2-clients/registration-tokens", summary: "List them. Metadata only — the handle is not stored, so it cannot be listed." },
        ],
      },
      {
        type: "note",
        text: "The three consent endpoints take **no** `user_id`: consent is the data subject's own (GDPR Art. 4(11)), so there is nothing for an administrator to give on somebody's behalf. `GET /api/v1/users/{user_id}/sessions` carries the `refresh_replay_verdict`, `refresh_replay_grace_accepted`, `refresh_replay_refused` and `refresh_replay_at` fields the admin UI's **Sessions** badges are drawn from — see [Authentication & sessions](#/docs/auth).",
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
        caption: "put a user in a group, check access",
        code: "# A service account gets a bearer token from the OAuth2 token endpoint.\n# (An interactive login sets cookies instead — see the Quickstart.)\nTOKEN=$(curl -sS -X POST 'https://iam.acme.dev/oauth2/token?tenant_id=<uuid>' \\\n  -d grant_type=client_credentials \\\n  -d client_id=\"$SA_CLIENT_ID\" -d client_secret=\"$SA_CLIENT_SECRET\" \\\n  | jq -r .access_token)\n\n# Groups admit a service-account token; the account's roles decide.\ncurl -sS -X POST \"https://iam.acme.dev/api/v1/groups/$GROUP/members\" \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d \"{\\\"user_id\\\":\\\"$USER_ID\\\"}\"\n\ncurl -sS -X POST https://iam.acme.dev/api/v1/authz/check \\\n  -H \"authorization: Bearer $TOKEN\" -H 'content-type: application/json' \\\n  -d '{\"action\":\"read\",\"resource_id\":\"<uuid>\"}'",
      },
      {
        type: "note",
        text: "**Correction.** Earlier versions of this example created the user with the same service-account token. `/api/v1/users` is a human-only family: it answers a service-account token with `401`, and did before `1.0.0-beta17` as well, when every management route took a user token only. Create users with an administrator's session, or provision them over [SCIM](#/docs/scim).",
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
        text: "Everything in the index above is reachable from any of the eleven SDKs as ordinary library code, not as hand-rolled HTTP. CONTRACT §27 defines that management surface, and it is generated rather than written: `sdks/management-registry.json` — the third artifact the SDKs vendor alongside `openapi.json` and the contract — classifies every operation in the spec into **24 namespaces** and names the **162** that make up the surface, and each SDK ships a generator over it plus a CI job that regenerates and diffs. So a new endpoint reaches every SDK by regeneration, and an SDK that has not regenerated fails its own build rather than quietly lagging.",
      },
      {
        type: "p",
        text: "The registry is explicit about what it leaves out, and why: the authentication endpoints (§1, §23, §25), the authorization checks (§1), the OAuth2 grants and relying-party helpers (§12, §14, §15, §26), UMA (§20), the WebAuthn ceremonies (§24) and the device-grant user-interaction endpoints (§14) are all protocol surfaces with their own hand-written contract sections. Management is the CRUD half, and only the CRUD half.",
      },
      {
        type: "list",
        items: [
          "**Namespaced, not flat.** Operations hang off a namespace handle — `client.service_accounts().rotate_secret(id)` — with a `client.management()` accessor beside it rather than instead of it. C is the one exception: it has no handle to hang operations on, so it gets the flat-symbol form.",
          "`search` **is applied server-side**, before `offset` and `limit`. On all twenty-one paginated operations. Filtering a page client-side is forbidden by the contract, because it silently changes what pagination means: page 2 of a filtered set is not the filtered part of page 2.",
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
        text: "Erasure pseudonymises the actor identity in the audit trail rather than deleting the records — an append-only log cannot have rows removed from it. The HMAC pepper that makes pseudonyms consistent is `AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER`; changing it breaks the linkage between old and new pseudonyms. See [Standards & compliance](#/docs/compliance).",
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
        text: "**Rate limits follow the family, not the service name.** `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` sizes the authorization service, and the token and userinfo services are a family of their own, by default five times that ceiling; `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` sizes `UserService` **and, since the beta11 remediation, the whole of** `ReactorAdminService` — which used to fall through to the authorization family's much larger ceiling. It defaults to **10/s per IP and deliberately does not move with the deployment posture**, because an administrative surface has no throughput case: reactor CRUD over gRPC above that rate needs the variable raised explicitly. See [Sizing your rate limits](https://github.com/ilpanich/axiam/blob/main/docs/deployment/rate-limit-sizing.md).",
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
      { type: "h", id: "client-certs", text: "TLS and client certificates" },
      {
        type: "p",
        text: "The listener terminates TLS itself when both of its certificate variables are set, with the same TLS 1.3-only posture and the same reloadable leaf as the REST listener. Since `1.0.0-beta17` it can also verify client certificates, **off by default**. Before that, its TLS configuration requested no client certificate and no setting could change it — on a listener that carries `ReactorAdminService` as well as `CheckAccess`, a bearer token was all any caller ever needed.",
      },
      {
        type: "table",
        headers: ["Key", "Purpose"],
        rows: [
          ["`AXIAM__GRPC_TLS_CLIENT_AUTH`", "`off` (default), `optional` or `required`."],
          ["`AXIAM__GRPC_TLS_CLIENT_CA_PATH`", "PEM bundle client certificates are verified against. Required unless `CLIENT_AUTH` is `off`."],
        ],
      },
      {
        type: "table",
        headers: ["Mode", "What the listener does"],
        rows: [
          ["`off`", "The listener as it has always been: no client certificate is requested, and one a client holds is never sent."],
          ["`optional`", "Asks for a certificate and verifies any that is presented. A client that presents none is still served on its token alone."],
          ["`required`", "Refuses the TLS handshake unless the client presents a certificate that chains to the bundle. No RPC runs before that check, so this is a network-level gate on the whole listener, `ReactorAdminService` included."],
        ],
      },
      {
        type: "p",
        text: "A verified certificate reaches the auth interceptor. The certificate is proof of possession and a gate; it is **not** an identity. Every call still needs a bearer token, and the token decides who the caller is.",
      },
      {
        type: "p",
        text: "**Boot is refused, not warned about**, when:",
      },
      {
        type: "list",
        items: [
          "`CLIENT_AUTH` is not one of the three words — including `optional_self_signed`, which exists for RFC 8705 self-signed OAuth2 clients, whose token endpoint is not served on this listener;",
          "`CLIENT_AUTH` is `optional` or `required` but `CLIENT_CA_PATH` is unset;",
          "`CLIENT_CA_PATH` is set but `CLIENT_AUTH` is `off`;",
          "the bundle is unreadable, unparsable or empty;",
          "either client-auth variable is set while the listener is **plaintext** (neither certificate variable set, or only one of them). A listener with no handshake cannot ask for a certificate, and serving cleartext on a port its operator believes is mutually authenticated is the worst outcome available.",
        ],
      },
      {
        type: "p",
        text: "**One anchor set, one reload.** Point `AXIAM__GRPC_TLS_CLIENT_CA_PATH` at the bundle the REST listener uses — `AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH`, or `client-ca-bundle.pem` beside `AXIAM__SERVER__TLS__CERT_PATH` — and flagging or unflagging a CA as an mTLS trust anchor in the admin console reloads **both** listeners without a restart. The gRPC listener has its own verifier, because its policy can differ from REST's (REST `optional` for browsers, gRPC `required` for the mesh), and on each reload it re-reads its own bundle. A reload that finds that file unreadable or empty logs an error and **keeps the previous anchors**; it never falls back to asking for nothing.",
      },
      {
        type: "note",
        text: "The names are **flat** — `AXIAM__GRPC_TLS_…`, with no further double underscore after `GRPC`, like the certificate variables; the nested spelling is not read. The keys are listed under [Configuration](#/docs/configuration#connectivity), and the [deployment guide](https://github.com/ilpanich/axiam/blob/main/docs/deployment/README.md#the-grpc-listener-tls-and-client-certificates) has the full reasoning.",
      },
      { type: "h", id: "device-tokens", text: "Certificate-bound device tokens over gRPC" },
      {
        type: "p",
        text: "In `1.0.0-beta17` the token `POST /api/v1/auth/device` returns carries an RFC 8705 `cnf.x5t#S256` claim over the certificate rustls verified when the device logged in, so it is not a bearer credential. (Behind a proxy that forwards the certificate in `X-Client-Certificate` the claim is deliberately not made.) Over gRPC the check reads the certificate rustls verified for **this** connection. With client authentication on, a device that presents the same certificate it logged in with is accepted over gRPC as it is over REST; with another device's certificate, or with none, its token is refused. Under the default, `off`, a certificate-bound token has no evidence to match and is **refused** — the fail-closed direction. A token minted before this change carries no `cnf` and is accepted exactly as it always was. See [PKI & certificates](#/docs/pki) for the login itself.",
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
      { type: "h", id: "rabbitmq", text: "Two things to decide before you put AXIAM in front of RabbitMQ" },
      {
        type: "p",
        text: "**A broker that demands a client certificate needs one AXIAM cannot issue yet.** Requiring a client certificate from every AMQPS connection — broker-wide `fail_if_no_peer_cert` — is the right posture, and it includes AXIAM's own client. That client connects during startup — before the REST API is listening, before an organization CA exists, and certainly before anything has called `POST /api/v1/certificates`. There is no ordering that lets AXIAM issue the certificate it needs in order to start.",
      },
      {
        type: "p",
        text: "So issue that one **offline, from the same root**: generate AXIAM's broker client certificate with the same CA (or an offline intermediate under it) that signs the rest of the fleet, mount it, and point `AXIAM__AMQP__TLS__CLIENT_CERT_PATH` / `AXIAM__AMQP__TLS__CLIENT_KEY_PATH` at it. Once AXIAM is up it can issue the *devices'* certificates from its own CA, and they chain to the same root the broker already trusts — the arrangement that makes one trust store serve both. `scripts/gen-broker-tls.sh` is the shape of this for a development stack; production wants your own CA and your own key custody. The alternative — bootstrapping against a broker that does not require peer certificates and tightening it afterwards — leaves a window in which it does not require them, and an operator who forgets step two.",
      },
      {
        type: "p",
        text: "**AXIAM's access tokens are not consumable by RabbitMQ's OAuth 2.0 backend.** `rabbitmq_auth_backend_oauth2` reads a JWT's `scope` claim and turns entries such as `rabbitmq.configure:%2f/*` into broker permissions. AXIAM's `scope` is an OAuth2 authorization-server claim describing scopes a client requested and was granted against AXIAM's own resources — an application-defined vocabulary the plugin's grammar has no bearing on. On the device path it is not merely different but absent: `POST /api/v1/auth/device` has no way to request a scope and a service account registers none, so the claim is omitted entirely, and a token with no `scope` grants no RabbitMQ permission.",
      },
      {
        type: "p",
        text: "The arrangement that works is **certificate login plus an HTTP auth backend**: `rabbitmq_auth_mechanism_ssl` takes the identity from the client certificate the device already presents, and `rabbitmq_auth_backend_http` asks a small endpoint of yours — free to call AXIAM's authorization API — for the vhost, resource and topic decisions. That keeps one identity per device, issued by AXIAM, and puts the permission model where RabbitMQ can express it.",
      },
      {
        type: "note",
        text: "Both are from the [deployment guide's broker chapter](https://github.com/ilpanich/axiam/blob/main/docs/deployment/README.md#two-things-to-decide-before-you-put-axiam-in-front-of-rabbitmq), new in `1.0.0-beta17`. Mapping AXIAM roles onto the plugin's `scope` grammar would mean minting a second, RabbitMQ-shaped token; that is not what these variables configure and is not covered there.",
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
          [
            "`phoneNumbers`, `addresses`",
            "Mapped onto the user on create, replace and patch. A `remove`, or an empty array, erases them.",
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
            code: 'POST /api/v1/roles\nPOST /api/v1/roles/{role_id}/permissions   { "permission_id": "<id of scim:provision>" }',
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
      { type: "h", id: "contact", text: "Provisioning a phone number is not releasing one" },
      {
        type: "p",
        text: "`phoneNumbers` and `addresses` provision the values onto the user record; **whether any relying party ever sees them is a separate decision**, taken by the four OIDC gates on the `phone` and `address` scopes — the organization's switch, the client registration, the end user's consent, and the FAPI profile exclusion. See [the `address` and `phone` scopes](#/docs/oauth2). A directory that syncs a telephone number has therefore not consented to anything on the user's behalf.",
      },
      { type: "h", id: "contention", text: "A concurrent PATCH that loses a race" },
      {
        type: "p",
        text: "Two provisioning writes that reach the same record at once are an optimistic-concurrency conflict in the datastore. AXIAM retries such a write, and one that **stays** lost answers `503` with the slug `write_contention` and `Retry-After: 1` — deliberately not `409`, which in SCIM means the request conflicts with the resource's *state* (RFC 7644 §3.12) and which a caller answers by changing the request, and deliberately not `500`, which an identity provider reads as a failed sync and answers by re-sending the whole record. Uniqueness violations and state preconditions still answer `409`, as they always did. See [Error reference](#/docs/errors).",
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
          {
            title: "Outbound SCIM provisioning →",
            body: "The other direction: AXIAM as the SCIM client, pushing this tenant's users and groups to downstream applications.",
            to: "docs",
            doc: "scim-outbound",
          },
        ],
      },
    ],
  },

  {
    slug: "scim-outbound",
    section: "APIs & integration",
    navLabel: "Outbound SCIM",
    title: "Outbound SCIM provisioning",
    intro:
      "Push this tenant's users and groups to the applications that keep their own account lists. You register a downstream SCIM 2.0 service provider as a target; AXIAM creates, updates, deactivates and deletes the matching accounts there as people change here, and repairs drift every night.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "what", text: "What it does" },
      {
        type: "p",
        text: "[SCIM provisioning](#/docs/scim) is the inbound direction: an identity provider pushes people *into* AXIAM. This is the other one. AXIAM is the **SCIM client** (RFC 7643, RFC 7644) and the system you register is the **service provider**: a SaaS application, a ticketing tool, a wiki — anything that exposes `/Users` and `/Groups` and would otherwise need an administrator to add and remove people by hand. When someone joins, changes name, moves team, is disabled or is erased in AXIAM, the application hears about it.",
      },
      {
        type: "list",
        items: [
          "**A target is one downstream.** A tenant can register several; each has its own URL, credential, scope and policy.",
          "**What is sent is a fixed set of attributes.** A user's `userName` (the AXIAM username, or the e-mail address, your choice), `name.givenName`, `name.familyName`, `displayName`, the primary `emails` value, `active` and `externalId`. A group's `displayName`, `externalId` and `members`. There is no mapping language, and no attribute is sent that is not in that list.",
          "**`externalId` is the AXIAM id**, and the id the downstream assigns is remembered on a *link* record. That pair is how AXIAM finds its own accounts again.",
          "**Delivery is level-triggered.** A change queues a *reference* (a user or group id and nothing else), and every attempt re-reads the target, the person and the link and sends what the downstream should look like *now*. Retries, reordering and duplicates therefore converge, and no attribute of a person ever sits in a queue.",
          "**Human administrators only.** The registry holds a credential to an outbound endpoint and decides where a tenant's people are sent, so a service-account token is refused with `401`. Reading needs `scim_targets:read`; registering, replacing, deleting and reconciling need `scim_targets:write`. Both are seeded per tenant.",
        ],
      },
      { type: "h", id: "register", text: "Register a target" },
      {
        type: "p",
        text: "In the console, **Identity → SCIM Targets**. Over the API it is `/api/v1/scim-targets` (the `scim_targets` namespace of the SDKs' management surface). The tenant is the one your token belongs to.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Get a credential from the downstream",
            body: "A bearer token, or an OAuth 2.0 client id and secret that can obtain a token with the client-credentials grant, with the right to manage users and groups through the downstream's SCIM endpoint.",
          },
          {
            title: "Create the target",
            body: "A name, the SCIM service root as `base_url`, how to authenticate, the credential, which users are in scope, and the policy. The credential is accepted here and **never returned by any call**.",
            code: 'POST /api/v1/scim-targets\n{\n  "name": "HR system",\n  "base_url": "https://scim.example.com/scim/v2",\n  "auth": { "type": "bearer" },\n  "credential": "<token>",\n  "scope": { "type": "all_users" },\n  "push_groups": false,\n  "user_name_from": "username",\n  "deprovision": "deactivate"\n}',
          },
          {
            title: "Let the first synchronisation run",
            body: "A target created enabled starts a reconciliation straight away, which queues a reference for every user and group in scope. Its progress is on the target: `GET /api/v1/scim-targets/{id}` carries the last success and failure, the consecutive failures, the dead-lettered total and the last reconciliation.",
          },
        ],
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/scim-targets", summary: "List the tenant's targets with their delivery state. Paged and searchable (name, base URL, id)." },
          { method: "POST", path: "/api/v1/scim-targets", summary: "Register a target. The credential is required and write-only." },
          { method: "GET", path: "/api/v1/scim-targets/{id}", summary: "One target and its delivery state. Never the credential." },
          { method: "PUT", path: "/api/v1/scim-targets/{id}", summary: "Replace the configuration. `409` when the target changed since it was read." },
          { method: "DELETE", path: "/api/v1/scim-targets/{id}", summary: "Delete the target, its links and its state. Nothing is deprovisioned downstream." },
          { method: "POST", path: "/api/v1/scim-targets/{id}/reconcile", summary: "Start a reconciliation now: `202` when claimed, `409` while one is running or the target is disabled." },
        ],
      },
      { type: "h", id: "auth", text: "Authentication and the credential" },
      {
        type: "table",
        headers: ["`auth.type`", "What AXIAM sends", "Needs"],
        rows: [
          ["`bearer`", "`Authorization: Bearer <token>` to `base_url`", "The token as `credential`."],
          [
            "`oauth2_client_credentials`",
            "A token request to `token_url` with the client id and secret, then `Authorization: Bearer <access token>` to `base_url`",
            "`auth.token_url`, `auth.client_id`, optionally `auth.scope`, and the secret as `credential`. The access token is cached in memory for at most an hour (less if the response says so) and never stored.",
          ],
        ],
      },
      {
        type: "list",
        items: [
          "**Write-only, and sealed at rest.** The credential is encrypted with AES-256-GCM under `pki_encryption_key` (`AXIAM__AUTH__PKI_ENCRYPTION_KEY`), the key webhook secrets use. No response carries it, and none says whether one is set. Without that key a write that carries a credential is `503`.",
          "**Bound to its URL.** A credential does not follow the endpoint it was registered for. Changing `base_url` of a bearer target, `auth.token_url` of a client-credentials target, or switching `auth.type` requires the credential again in the same write, and is `400` naming the field otherwise. Without this rule an administrator who may edit a target but not read its credential could aim the stored one at a host they control. Leaving the credential out of a replacement otherwise keeps the stored one.",
          "**Two administrators, no lost update.** A replacement is conditional on the version it read: if another administrator saved first, it is `409` and nothing is written. Reload and retry.",
          "**The URL is checked twice.** At write time `base_url` and `token_url` are held to the webhook address policy: `https`, no credentials or fragment in the URL, at most 2 048 bytes, no IP literal that is not publicly routable and no `localhost`, `*.local` or `*.internal` name. At delivery every request resolves the host *again* and goes only to a publicly routable address, with the validated address pinned and **no redirect followed**, so a name that later points somewhere private, or a downstream that redirects, cannot carry the credential or a person's attributes anywhere you did not name.",
        ],
      },
      { type: "h", id: "scope", text: "Scope and groups" },
      {
        type: "table",
        headers: ["`scope`", "Who is provisioned"],
        rows: [
          ["`{ \"type\": \"all_users\" }`", "Every user of the tenant whose status is *active*."],
          ["`{ \"type\": \"groups\", \"group_ids\": [...] }`", "Users who are **direct members** of any listed group (1 to 100 groups of this tenant; each is checked when you save). Membership through nesting or through a role is not followed."],
        ],
      },
      {
        type: "p",
        text: "`push_groups` also creates the groups downstream, with their members: every group of the tenant for `all_users`, the listed groups otherwise. A group's `members` are the downstream ids of the users that are linked, so a member appears there once the user does. A group with more than 10 000 members is not pushed (it is dead-lettered with that reason).",
      },
      { type: "h", id: "deprovision", text: "Deprovisioning and erasure" },
      {
        type: "table",
        headers: ["The user", "What happens downstream"],
        rows: [
          ["Active and in scope, not yet there", "`POST /Users` with `externalId` set to the AXIAM id. A `409` from the downstream is resolved by looking the account up by `externalId`: exactly one match is adopted; anything else is dead-lettered as a conflict."],
          ["Active and in scope, already linked", "`PATCH` with `replace` operations on the mapped attributes only, skipped when nothing changed since the last send. Never a `PUT`: attributes the downstream owns are not overwritten."],
          ["Leaves scope, or is disabled or otherwise not active", "Per `deprovision`: **`deactivate`** (the default) sets `active` to `false`; **`delete`** removes the account. A user who was never provisioned there is not created in order to be deactivated."],
          ["Deleted or **erased** (GDPR)", "**`DELETE`, whatever `deprovision` says.** The link record survives the erasure only until that `DELETE` succeeds; it holds ids and a digest, never a personal attribute. A `DELETE` that is dead-lettered is retried by the nightly reconciliation."],
        ],
      },
      {
        type: "note",
        text: "Deprovisioning and erasure are different decisions. A person who leaves a team is *deactivated* (or deleted) according to the target's policy, because you may want the account's history downstream. A person who exercises the right to erasure is *deleted* from every target, always.",
      },
      { type: "h", id: "triggers", text: "What triggers a push" },
      {
        type: "p",
        text: "Changes are reported by the user and group stores themselves, after a write succeeds, so every writer is covered with nothing to configure: the console and the REST API, SCIM inbound, directory just-in-time provisioning and sync, SAML and OIDC federation sign-ins, and GDPR erasure. A user update pushes only when it touches something provisioned (username, e-mail, status, name and display fields), so a sign-in's bookkeeping queues nothing. A group's creation, rename, deletion and membership changes push, and linking a user also queues the groups they are in. A queue that is down never fails the change that caused it: the change is logged and the nightly reconciliation catches it.",
      },
      { type: "h", id: "reconcile", text: "Reconciliation" },
      {
        type: "p",
        text: "Delivery cannot see a change nobody reported: a downstream administrator who edited or deleted an account, a message lost to a broker outage, an erasure the downstream refused. Reconciliation is the repair. It runs **nightly for every enabled target**, claimed in the datastore so that one replica runs it, and on demand with *Reconcile now* (`POST /api/v1/scim-targets/{id}/reconcile`) under the same claim: a second request while a run is held, or within five minutes of one, is `409`.",
      },
      {
        type: "list",
        items: [
          "It **queues a reference** for every user and group in scope and for every linked resource, and the deliverer converges each.",
          "It **reads the downstream** (`GET /Users`, and `/Groups` when groups are pushed, 100 at a time, within a page and a time budget). A linked account whose downstream form differs from what AXIAM would send has its digest cleared so the next sync re-sends it; a link whose downstream account has gone is dropped and the account created again.",
          "It **deprovisions** a downstream account whose `externalId` names a user of this tenant that is out of scope, disabled or erased.",
        ],
      },
      { type: "h", id: "untouched", text: "What is never touched downstream" },
      {
        type: "p",
        text: "AXIAM only ever acts on accounts it created or adopted by `externalId`. A downstream account with no `externalId`, with one that is not an AXIAM id, or with the id of a user of *another tenant*, is an account the application made for itself: reconciliation never updates, deactivates or deletes it, and AXIAM never deletes accounts it does not know. **Deleting a target does not deprovision anything either**: the accounts AXIAM created stay in the service provider and AXIAM forgets them. To remove them, set `deprovision` to `delete`, let AXIAM push, and delete the target afterwards.",
      },
      { type: "h", id: "limits", text: "Delivery limits and retries" },
      {
        type: "p",
        text: "One attempt is one pass of read, decide and send. The deliverer reports the outcome and the dispatcher decides what happens next, as for webhooks and SSF.",
      },
      {
        type: "table",
        headers: ["The downstream answers", "Outcome"],
        rows: [
          ["`2xx`", "Delivered. A `404` on a `DELETE` also counts as done."],
          ["`408`, `429`, `5xx`, a timeout, a connection failure, a redirect", "Retried with backoff. A redirect is never followed."],
          ["`401` on a client-credentials target", "The cached access token is dropped and the attempt retried."],
          ["`401` or `403` on a bearer target, and any other `4xx`", "Dead-lettered: retrying will not change the answer until someone fixes the credential or the request."],
          ["`404` on a `PATCH`", "The link is dropped and the account created again."],
          ["The target is disabled or deleted since the message was queued", "Dead-lettered (`target disabled`, `target not found`)."],
        ],
      },
      {
        type: "list",
        items: [
          "**Per request:** 10 seconds from connect to last byte; a response body is read to 64 KiB (1 MiB for a list) and never logged.",
          "**Retry schedule:** up to five attempts with exponential backoff from five seconds to one hour. The three variables are `AXIAM__SCIM_PUSH__MAX_ATTEMPTS`, `AXIAM__SCIM_PUSH__BACKOFF_BASE_MS` and `AXIAM__SCIM_PUSH__BACKOFF_CEILING_MS`; see [Webhooks → retry](#/docs/webhooks) for the table.",
          "**Ordering is not promised and is not needed**, because each attempt computes the desired state fresh.",
          "**Rate limit:** the registry's four writes (create, replace, delete, reconcile now) each have a per-IP bucket under `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN` (default 30 a minute); reads are not limited, and no rate-limit profile moves it.",
        ],
      },
      { type: "h", id: "failures", text: "Failures and notifications" },
      {
        type: "p",
        text: "Every target carries its own delivery state, which is how you see that a downstream is refusing AXIAM: `last_success_at`, `last_failure_at`, a `last_failure_reason`, `consecutive_failures`, `dead_lettered_total` and `last_reconciled_at`. The reason is always one of a fixed set of short phrases (for example that the receiver refused the credential, answered with an HTTP status, or could not be reached): never a URL, a response body or a value.",
      },
      {
        type: "p",
        text: "A dead letter is recorded as an audit row, `scim_push.delivery_failed`. To be told, create a **notification rule** for the event type `scim_delivery_failed` (`/api/v1/notification-rules`): it mails the tenant's administrators through the same mechanism as every other rule, with no separate channel. The audit rows for the registry itself are `scim_target.created`, `scim_target.updated`, `scim_target.deleted` and `scim_target.reconcile_requested`; they name what changed and never a URL or a credential.",
      },
      { type: "h", id: "queues", text: "The AMQP queues" },
      {
        type: "p",
        text: "Outbound SCIM is the third kind on the outbound dispatcher and has queues of its own, declared at startup: `axiam.scim_push`, `axiam.scim_push.retry` (the delay between attempts) and `axiam.scim_push.dlq` (dead letters). The webhook and SSF queues are untouched. A message is `{ target_id, resource_type, axiam_id }` and nothing else; the dead-letter queue discards after seven days, because the ids are user ids. They are described in `docs/api/asyncapi.yml`.",
      },
      { type: "h", id: "not-supported", text: "What is not supported" },
      {
        type: "list",
        items: [
          "**No attribute mapping language.** The attribute set is fixed; the only choice is whether `userName` is the username or the e-mail address.",
          "**No enterprise-user or custom schema extensions, no `password`, no roles or entitlements, no photos or addresses.**",
          "**No SCIM `Bulk`, and no `PUT` replace.** Users and groups are created with `POST`, changed with `PATCH` and removed with `DELETE`.",
          "**No nested groups and no membership through roles.** Scope follows direct group membership.",
          "**No two-way sync.** Nothing is read back into AXIAM; the downstream is only read to find drift, and its own accounts are left alone.",
          "**No private downstream.** A service provider on a private address, a `.local` or `.internal` name or plain `http` is refused, at write time and again at delivery.",
          "**No deprovisioning on delete,** as above.",
        ],
      },
      {
        type: "links",
        links: [
          {
            label: "CONTRACT §31 — Outbound SCIM targets",
            href: contractLink("31"),
            note: "The normative text: shapes, every server rule an SDK can observe, error mapping, and `Sensitive<T>` for the credential.",
          },
          {
            label: "RFC 7644 — SCIM protocol",
            href: "https://www.rfc-editor.org/rfc/rfc7644",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "SCIM provisioning (inbound) →",
            body: "The other direction: let Okta, Entra or another IdP push people into AXIAM.",
            to: "docs",
            doc: "scim",
          },
          {
            title: "Webhooks →",
            body: "The retry schedule outbound deliveries share, and event notifications for systems that are not SCIM.",
            to: "docs",
            doc: "webhooks",
          },
        ],
      },
    ],
  },

  {
    slug: "directory",
    section: "APIs & integration",
    navLabel: "LDAP / Active Directory",
    title: "LDAP and Active Directory",
    intro:
      "Let a tenant's people sign in with the directory they already run. The directory checks the password, AXIAM never stores it, and the directory's groups map onto AXIAM groups, so roles keep working.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "what", text: "What it does" },
      {
        type: "p",
        text: "A tenant points AXIAM at one LDAP or Active Directory server. At sign-in AXIAM looks the person up with a read-only **service account**, then binds **as that person** with the password they typed — the directory's own answer is the answer. The password and any hash of it are never kept. Multi-factor, passkeys and sessions then proceed exactly as for any other user. Signing in needs **nothing new from a client or an SDK**: a directory account calls the same `login`.",
      },
      {
        type: "list",
        items: [
          "**Read-only.** AXIAM never adds, modifies, deletes or changes a password in the directory.",
          "**Provisioned just in time**, if you switch that on: the first successful sign-in for a name that matches no local account creates one.",
          "**Groups map by an explicit table** you maintain — a directory group has to be named in it to put anyone anywhere. There is no match by name and no AXIAM group is ever created from a directory one.",
          "**Kept in step by a sync job** that deactivates (never deletes) accounts the directory dropped or disabled.",
          "**Not Kerberos.** Single sign-on through SPNEGO is out of scope; this is password sign-in checked by the directory.",
        ],
      },
      { type: "h", id: "before", text: "Before you start" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["You need", "Why"],
        rows: [
          [
            "A read-only bind account",
            "AXIAM binds as it only to search. Give it read rights on the user subtree (and the group subtree) and nothing else; on Active Directory an ordinary domain user is enough.",
          ],
          [
            "`AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY`",
            "Encrypts the bind secret at rest. Without it the feature is unavailable: a write that carries a secret is refused with `503`.",
          ],
          [
            "TLS the directory's certificate can pass",
            "`ldaps://`, or `ldap://` with StartTLS — plaintext is refused when you save. The certificate must name the host in the URL and chain to the tenant's trust anchors (or, with none given, a public root). Verification cannot be switched off.",
          ],
          [
            "A host name AXIAM may connect to",
            "The address is checked when you save and at every connection: loopback, link-local, the cloud metadata service, AXIAM's own listener and IPv6 literals are always refused, and a private address needs the operator to list its network in `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`.",
          ],
          [
            "A tenant that is not in `opaque_mode = required`",
            "Under `required` the tenant refuses password sign-in before reading a password, so directory accounts could not sign in. The two are refused together, in both directions, with a `409`.",
          ],
        ],
      },
      { type: "h", id: "configure", text: "Configure it" },
      {
        type: "p",
        text: "One configuration per tenant, under `/api/v1/tenants/{tenant_id}/directory` for the caller's own tenant, or on the console's **Directory** page. `PUT` creates or replaces; `PATCH` changes only the members you send, and an explicit `null` clears `group_base_dn` or `group_filter`.",
      },
      {
        type: "code",
        caption: "Create a configuration (the bind secret is write-only)",
        code: 'PUT /api/v1/tenants/{tenant_id}/directory\n{\n  "enabled": true,\n  "kind": "active_directory",\n  "url": "ldaps://dc1.corp.example.com",\n  "start_tls": false,\n  "bind_dn": "CN=axiam-ro,OU=Service,DC=corp,DC=example,DC=com",\n  "bind_secret": "<entered once, never returned>",\n  "base_dn": "OU=People,DC=corp,DC=example,DC=com",\n  "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",\n  "jit_provisioning": true,\n  "trust_anchors_pem": ["-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n"]\n}',
      },
      {
        type: "p",
        text: "`kind` only chooses defaults (`sAMAccountName` / `objectGUID` / `memberOf` for Active Directory; `uid` / `entryUUID` / reverse `member` search for OpenLDAP). A replacement **resets every member it omits to its default**; use `PATCH` to change one thing.",
      },
      {
        type: "p",
        text: "Every write is validated and the host is checked before anything is stored, on the URL **as written** — so a name that was re-pointed since the last save is caught by the next write that leaves the directory enabled, even if the URL did not change (a write that leaves it disabled opens no connection and skips the host check, so a directory can always be switched off). A refusal is a `400` that names the rule and never echoes the secret.",
      },
      { type: "h", id: "secret", text: "The bind secret is write-only" },
      {
        type: "p",
        text: "No response carries it, a flag that says one is set, or a hash of it, and the console never pre-fills it. Leave it out of a write that does not touch the connection and the stored one is kept.",
      },
      {
        type: "warn",
        text: "Changing the `url`, `start_tls`, `bind_dn` or `trust_anchors_pem` **requires entering the bind secret again** — without it the write is a `400` and changes nothing. A kept secret sent to a new host, through a trust anchor the editor chose, would be the secret handed to whoever runs that host. The console asks for it the moment you edit any of the four.",
      },
      { type: "h", id: "email", text: "An entry needs an e-mail address" },
      {
        type: "p",
        text: "A local account must have an e-mail address and AXIAM does not invent one — a placeholder would be released as the user's e-mail `NameID` and as the OIDC `email` claim. With provisioning on, a first sign-in for an entry whose mapped e-mail attribute is missing or unusable is the ordinary invalid-credentials failure, and the audit log records `directory.jit_refused` with the reason `unusable_attributes`. Active Directory entries without `mail` are the usual case: fill the attribute in, or map `user_attribute_map.email` to one every entry has.",
      },
      { type: "h", id: "groups", text: "Groups" },
      {
        type: "p",
        text: "`group_mappings` is a list of `{ directory_group_dn, group_id }`, at most 500, each `group_id` a group of the same tenant. Members of a directory group are put into the AXIAM group at **every** directory sign-in and by the sync job, nested groups followed to `group_nesting_depth`. The mapping owns only the memberships it made: one an administrator added by hand is never touched. If the directory cannot be asked, the sign-in fails rather than keep memberships that may have been revoked.",
      },
      { type: "h", id: "linking", text: "Linking an existing account" },
      {
        type: "p",
        text: "Provisioning only ever **creates**: it never turns an existing local account into a directory account, so a directory administrator cannot take over a local `admin` by creating a matching entry. Linking is the explicit administrator act that does — the directory finds the entry from the account's own username (you name only the account).",
      },
      {
        type: "warn",
        text: "Linking signs the owner out **everywhere**: their passkeys and security keys are deleted, so is any social or upstream-IdP identity linked to the account, their user certificates are revoked, and every session and refresh token revoked. Their authenticator-app (TOTP) enrolment is kept. There is no unlink. Repeating the call on an account already linked to that entry is a `200` that runs the revocations again — the way an interrupted link is completed.",
      },
      { type: "h", id: "sync", text: "Sync, disabling and deleting" },
      {
        type: "p",
        text: "A job on the server's cleanup schedule keeps accounts in step with the directory while it is enabled. An entry that vanished or was disabled sets the account `Inactive` — never `Deleted` — and revokes its sessions; nothing is ever re-enabled, created or linked by the job. A full run that would deactivate more than 10% of a tenant's directory accounts (and at least 5) applies nothing and reports `safety_valve`. `GET …/directory/sync-status` shows the last result and times.",
      },
      {
        type: "note",
        text: "Disabling or deleting the configuration stops the directory and only that. Directory accounts can no longer sign in with a password and the job stops, but sessions, refresh tokens and passkeys they hold keep working until they expire or an administrator deactivates the accounts. The audit row records how many live directory accounts the tenant had.",
      },
      { type: "h", id: "endpoints", text: "Endpoints" },
      {
        type: "api",
        endpoints: [
          {
            method: "GET",
            path: "/api/v1/tenants/{tenant_id}/directory",
            summary: "The configuration, without the secret. `404` until one is saved.",
          },
          {
            method: "PUT",
            path: "/api/v1/tenants/{tenant_id}/directory",
            summary: "Create (`201`) or replace (`200`) the configuration.",
          },
          {
            method: "PATCH",
            path: "/api/v1/tenants/{tenant_id}/directory",
            summary: "Change only the members sent; `null` clears `group_base_dn` / `group_filter`.",
          },
          {
            method: "DELETE",
            path: "/api/v1/tenants/{tenant_id}/directory",
            summary: "Remove the configuration and its sync state (`204`).",
          },
          {
            method: "POST",
            path: "/api/v1/tenants/{tenant_id}/directory/links",
            summary: "Link an existing account to its directory entry; signs the owner out everywhere.",
          },
          {
            method: "GET",
            path: "/api/v1/tenants/{tenant_id}/directory/sync-status",
            summary: "The sync job's last result and times; nulls before the first run.",
          },
        ],
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Answer", "When"],
        rows: [
          ["`400 validation_error`", "A rule refused the write — it names the rule — or the connection moved without the bind secret."],
          ["`403 authorization_denied`", "Another tenant's id, or a missing permission."],
          ["`404 not_found`", "No configuration; or, for linking, no such account or no single directory entry for its username."],
          ["`409 conflict`", "An enabled directory under `opaque_mode = required`; or, for linking, no enabled directory, an entry linked elsewhere, or an account linked to a different entry."],
          ["`429`", "More than 30 writes a minute from one address (`AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN`); reads are not limited."],
          ["`503 service_unavailable`", "No directory encryption key on the deployment, or the directory could not be asked."],
        ],
      },
      {
        type: "p",
        text: "Three permissions, held by the `admin` and `super-admin` roles: `directory:read`, `directory:write` and `directory:link` (kept apart because linking acts on a person, not on the configuration). A service-account token is not accepted: the bind secret is a human administrator's to enter. Changes write `directory.config_created`, `directory.config_updated` and `directory.config_deleted` audit rows with the names of the fields that changed and whether the connection moved — never the secret.",
      },
      {
        type: "links",
        links: [
          {
            label: "CONTRACT §30 — Directory configuration",
            href: contractLink("30"),
            note: "The normative text: shapes, every server rule an SDK can observe, error mapping, and `Sensitive<T>` for the bind secret.",
          },
          {
            label: "Deployment guide — What a tenant's directory needs",
            href: `${GH_BLOB}/docs/deployment/README.md`,
            note: "The operator's side: the encryption key, the address guard and the private-network allow-list, the frame cap, and the sync job.",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Federation (SAML & OIDC) →",
            body: "Sign-in through an external identity provider rather than a directory password.",
            to: "docs",
            doc: "federation",
          },
          {
            title: "SCIM provisioning →",
            body: "Let an IdP push users and groups instead of AXIAM reading them from a directory.",
            to: "docs",
            doc: "scim",
          },
        ],
      },
    ],
  },

  {
    slug: "saml-idp",
    section: "APIs & integration",
    navLabel: "SAML identity provider",
    title: "AXIAM as a SAML identity provider",
    intro:
      "Let the applications your tenant already runs sign people in with AXIAM over SAML 2.0. Each tenant is its own identity provider with its own signing certificate, issued by the tenant's own CA, and every assertion it issues is signed.",
    blocks: [
      { type: "h", id: "what", text: "What it does" },
      {
        type: "p",
        text: "The other direction of [Federation](#/docs/federation): there AXIAM is the *service provider* and trusts an external identity provider; here AXIAM is the **identity provider** and a service provider you register trusts AXIAM. A service provider (SP) is any application with a SAML library — a wiki, a ticketing system, a vendor's hosted product. The person signs in to AXIAM exactly as anywhere else, so multi-factor, passkeys, OPAQUE and the session policy all apply unchanged, and AXIAM tells the SP who they are in a signed assertion.",
      },
      {
        type: "list",
        items: [
          "**One identity provider per tenant.** Its entity id, metadata and endpoints are all under the tenant's own path, so a tenant's service providers never see another tenant's identity or key.",
          "**Web Browser SSO, both ways in.** SP-initiated sign-on takes the SP's `AuthnRequest` on the HTTP-Redirect or the HTTP-POST binding. IdP-initiated sign-on is a per-SP opt-in that is off by default.",
          "**Assertions are always signed.** There is no setting that turns that off, and no way to register an SP that would receive an unsigned one. Signing the surrounding `Response` too is a per-SP choice, on by default. The assertion is delivered to the SP's registered HTTP-POST consumer endpoint.",
          "**A pairwise, persistent `NameID` by default.** The identifier an SP sees is derived from the user *and that SP*, so two SPs cannot tell they are talking about the same person. An e-mail `NameID` is available per SP, and is released only for an address AXIAM has verified (or an active account).",
          "**A signing credential AXIAM issues for you.** The certificate is issued by the tenant's signing CA and its private key is generated and sealed on the server, never shown and destroyed when the credential is retired. You do not export a key from somewhere else and import it.",
          "**Rotation without a flag day.** Issue the next credential, let SPs pick up the metadata that now publishes both, then promote it.",
          "**Single logout.** Each SP gets its own random `SessionIndex`; a signed logout request from an SP ends the AXIAM session, and the other SPs that registered a logout endpoint are told one at a time through the browser.",
        ],
      },
      { type: "h", id: "enable", text: "Switch it on" },
      {
        type: "p",
        text: "Two things have to be true before a tenant answers a single SAML request, and until they are every SAML route replies with the same empty `404` — so nobody can tell from outside whether a tenant exists, or serves SAML at all.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Requirement", "Detail"],
        rows: [
          [
            "A server built with the `saml` feature",
            "It is on by default and links `libxml`; a build made with `--no-default-features` (CI's *Build (SAML off)* job) serves no SAML. The registry and credential API below are compiled into every build, so an administrator can prepare everything on such a server and read the answer to *is SAML available here* from `GET …/saml/idp`.",
          ],
          [
            "`saml_idp_enabled` is on for the tenant",
            "A layered setting, **off by default**, with the shape of `sensitive_scopes_enabled`: the organization turns it on and a tenant may only turn it *off* again. Set it through the settings API (see [Settings](#/docs/settings)); the console explains the setting but has no control for it yet.",
          ],
        ],
      },
      {
        type: "p",
        text: "Registering service providers and issuing the credential do **not** depend on the setting, so you can finish the whole configuration first and switch the identity provider on last. The metadata endpoint additionally answers `404` until the tenant has an active or a next credential, because metadata without a key is of no use to an SP.",
      },
      { type: "h", id: "endpoints", text: "The SAML endpoints" },
      {
        type: "p",
        text: "These are browser and SP-to-IdP routes, not API calls: an SP's own SAML library speaks to them, none takes a bearer token, and they are not in the OpenAPI document. `{tenant}` is the tenant's id in its canonical form, and the base is the deployment's public URL.",
      },
      {
        type: "table",
        headers: ["Path under `/saml/v2/{tenant}`", "What it is"],
        rows: [
          ["`/metadata`", "The identity provider's metadata (`GET` and `HEAD`), and its entity id — the entity id **is** the metadata URL. Paste this one URL into the SP."],
          ["`/sso`", "Single sign-on: the SP's `AuthnRequest` by `GET` (HTTP-Redirect) or `POST` (HTTP-POST)."],
          ["`/sso/idp-initiated?sp=<entity id>`", "IdP-initiated sign-on, for an SP registered with `allow_idp_initiated`. It is meant for AXIAM's own pages and bookmarks, and refuses a cross-site request."],
          ["`/sso/continue`", "The second leg of every sign-on, where the browser's session is resolved. Never called by an SP."],
          ["`/slo`", "Single logout on both bindings: a signed `LogoutRequest` or `LogoutResponse` from an SP."],
          ["`/sso/logout`", "IdP-initiated logout: ends the signed-in browser's session and walks it through the SPs that hold one."],
        ],
      },
      {
        type: "p",
        text: "The metadata is unsigned: it is served from your deployment's origin, so TLS to that origin is the trust anchor, and an SP administrator who wants more can compare the credential's SHA-256 fingerprint, which the console and the API both show. It advertises the signing certificate or certificates, both `NameID` formats, and the sign-on and logout locations — never a route that does not exist — and is cacheable for an hour with an `ETag`.",
      },
      { type: "h", id: "register", text: "Register a service provider" },
      {
        type: "p",
        text: "In the admin console, **SAML Service Providers** (`/saml`, in the *Identity* group of the sidebar, visible with `saml_sp:read`) lists, creates, edits and deletes registrations and shows the identity provider's entity id, metadata URL and endpoints with whether it is currently serving. The same operations are a REST API under `/api/v1/tenants/{tenant_id}/saml`, which is also what the SDKs' `saml` namespace calls.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Import the SP's metadata, or enter it by hand",
            body: "`parse-sp-metadata` takes either an uploaded document or an `https` URL and returns a **draft** registration with the certificate fingerprints and a list of warnings. It stores nothing. AXIAM fetches a URL only through its outbound address guard, refuses any document that declares a DTD or entity, and takes nothing as trusted from an unsigned document — a signature in it is reported, not evaluated. Two things that real SP metadata carries and a strict XML reader rejects are normalised on the parsed document, each with a warning in the draft: a `cacheDuration` on the `SPSSODescriptor` is dropped, and an `AssertionConsumerService` with no `index` is given the lowest unused one. You review the draft, then save it.",
            code: 'POST /api/v1/tenants/{tenant_id}/saml/parse-sp-metadata\n{ "metadata_url": "https://wiki.example.com/saml/metadata" }',
          },
          {
            title: "Save the registration",
            body: "Every write is validated before anything is stored. The `entity_id` is unique within the tenant and **cannot be changed later** — the pairwise `NameID` is keyed on it, so a different id would give every user a new account at that SP; register a new SP instead. The consumer-endpoint list is an allow-list held to the rules of an OAuth2 redirect URI (absolute, `https` — `http` only for loopback — no `*`, no fragment), checked byte for byte against the request.",
            code: 'POST /api/v1/tenants/{tenant_id}/saml/service-providers\n{\n  "display_name": "Team wiki",\n  "entity_id": "https://wiki.example.com/saml/metadata",\n  "acs_urls": [\n    { "url": "https://wiki.example.com/saml/acs", "binding": "http_post", "index": 0, "is_default": true }\n  ],\n  "name_id_format": "persistent",\n  "sp_signing_cert_pem": "<PEM certificate>",\n  "attribute_mappings": [\n    { "saml_name": "mail", "source": "email" }\n  ],\n  "allowed_groups": []\n}',
          },
          {
            title: "Decide who may sign in",
            body: "`allowed_groups` limits the SP to members of those groups. **An empty list means every active user of the tenant.** A disabled SP is refused at every sign-on; logout keeps working for it.",
          },
          {
            title: "Give the SP the metadata URL",
            body: "Hand the SP `GET …/saml/v2/{tenant}/metadata`, or the entity id, sign-on and logout locations shown on the console page, and have it trust the credential below.",
          },
        ],
      },
      {
        type: "p",
        text: "`PUT` is a **replacement**: any member you leave out takes its default, it is not kept. Read the registration, change what you need, and send the whole thing back. The attribute table maps AXIAM's `username`, `email`, `display_name`, `given_name`, `family_name`, `groups` and `roles` onto the attribute names the SP expects. If an SP signs its requests, register its certificate; with `want_authn_requests_signed` an unsigned request is refused, and a logout request from an SP is accepted only when it is signed by that certificate. **The SP must sign with a SHA-256 or stronger digest**: AXIAM refuses SHA-1 on signed requests, and `samael`'s default `Signature::template` uses a SHA-1 digest, so an SP built on it has to set the digest to SHA-256.",
      },
      { type: "h", id: "credential", text: "The signing credential" },
      {
        type: "p",
        text: "A tenant holds at most one `active` and one `next` credential; a `retired` one has had its key destroyed. All three states are listed by `GET …/saml/idp-credentials`, which returns public facts only — the certificate, serial, fingerprint, validity and status, and no key of any kind. It needs one of the tenant's active signing CAs to issue from, and key generation takes a few seconds.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Issue the first credential",
            body: "Into the empty `active` slot. `validity_days` is 1 to 730 (default 365) and never beyond the CA's own expiry.",
            code: 'POST /api/v1/tenants/{tenant_id}/saml/idp-credentials\n{ "issuer_ca_id": "<signing CA id>", "slot": "active" }',
          },
          {
            title: "To rotate, issue the next one",
            body: "Into the `next` slot. Metadata now publishes **both** certificates, active first. Wait at least the metadata's one-hour cache and your SPs' own refresh interval.",
            code: '{ "issuer_ca_id": "<signing CA id>", "slot": "next" }',
          },
          {
            title: "Promote it",
            body: "`POST …/idp-credentials/{credential_id}/promote` names the current `next` credential; in one transaction the old `active` is retired and its key destroyed and `next` becomes `active`. Naming anything else, or a credential outside its validity window, is a `409`.",
          },
        ],
      },
      {
        type: "warn",
        text: "**Retiring the active credential with no successor stops SAML sign-on for the whole tenant at once.** That is deliberate — it is the response to a leaked key — and the console says so before it asks. Retiring is also the only way to stop a key you no longer trust from signing.",
      },
      {
        type: "p",
        text: "Issuing, promoting and retiring need `saml_idp:credential`, kept apart from `saml_sp:write` because one call can change sign-on for every SP of the tenant. These credentials are not certificates in the PKI sense: they never appear in the certificate list, and certificate issuance, CSR signing, the bind endpoint, device login and mTLS all refuse them.",
      },
      { type: "h", id: "keys", text: "The pairwise key — never change it" },
      {
        type: "p",
        text: "The persistent `NameID` is an HMAC under a deployment secret, `AXIAM__AUTH__SAML_PAIRWISE_KEY`, deliberately independent of the signing credential so that rotating the credential never changes anyone's identifier. It is optional, and **without it a sign-on to an SP that uses the persistent format fails** with a SAML `Responder` status.",
      },
      {
        type: "warn",
        text: "Set it once and keep it for the life of the deployment. Changing it, losing it or restoring a backup without it gives every user a new, unknown account at every SP that uses persistent identifiers. It is read from the environment or from your secret provider, like the other deployment keys; see [Configuration](#/docs/configuration).",
      },
      { type: "h", id: "limits", text: "Rate limits" },
      {
        type: "p",
        text: "Every route is rate limited per client address. The six browser routes each have a bucket of their own — `saml_idp_sso`, `saml_idp_sso_continue`, `saml_idp_sso_idp_initiated`, `saml_idp_metadata`, `saml_idp_slo` and `saml_idp_sso_logout` — all sized by `AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` (default 30 a minute), so a flood on one cannot spend another's allowance, or `/oauth2/end_session`'s. The seven administrative writes have one bucket per route under `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN` (default 30); reads are not limited. See the [configuration reference](#/docs/configuration).",
      },
      { type: "h", id: "logout", text: "Single logout" },
      {
        type: "p",
        text: "AXIAM records, for each sign-on, which SP was given which `NameID` and `SessionIndex`. A `LogoutRequest` is honoured only if it is signed by the certificate registered for that SP and names a session that SP really holds. AXIAM then **revokes the whole AXIAM session first** — back-channel logout to its OIDC clients, then the ordinary revocation, which also reaches the revocation feed — and only then walks the browser through the other SPs, each with a signed request, one at a time. A chain that stalls midway never leaves an AXIAM session alive; the initiating SP is told `Success`, or `PartialLogout` if some SP could not be reached.",
      },
      {
        type: "warn",
        text: "SAML logout runs only when the logout starts at a SAML endpoint. `/oauth2/end_session`, an administrator revoking a session, a password reset and an account being disabled all end the AXIAM session but do not walk the SPs — those SPs learn nothing until their own session expires or their next sign-on request is refused. An API call cannot lead a browser through other sites. This is a recorded, accepted limit in the threat model.",
      },
      { type: "h", id: "unsupported", text: "What it does not do" },
      {
        type: "list",
        items: [
          "**Assertion encryption.** Not implemented. An SP registered with `encrypt_assertions` is refused when you save it, and AXIAM never falls back to sending a plaintext assertion to an SP that asked for encryption. The metadata advertises no encryption key.",
          "**Unsigned assertions.** There is no such mode.",
          "**Signed metadata.** AXIAM's own metadata is unsigned (see above), and a signature on an SP's imported metadata is not evaluated, because there is nothing independent to evaluate it against.",
          "**Artifact and SOAP bindings.** Sign-on and logout use HTTP-Redirect and HTTP-POST only, and an SP's consumer endpoint must be HTTP-POST.",
          "**Refreshing an SP's metadata on its own.** Metadata import is a person's act; AXIAM never re-reads a URL later, so a compromised SP host cannot quietly swap its certificate and endpoints.",
          "**A SAML logout chain from other logouts**, as above.",
          "**Anything in the SDKs' browser path.** The SDKs administer the registry and the credential; no SDK builds an `AuthnRequest` or consumes an assertion. That is the SP's SAML library's job.",
        ],
      },
      { type: "h", id: "api", text: "Management endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/saml/idp", summary: "The identity provider as the tenant sees it: entity id, metadata, sign-on and logout URLs, whether SAML is available and enabled, and the active and next credential ids." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/saml/service-providers", summary: "List registered service providers (paged, searchable)." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/saml/service-providers", summary: "Register one (`201`)." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}", summary: "Replace it. `entity_id` cannot change." },
          { method: "DELETE", path: "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}", summary: "Remove it and its session records. Ends no session at the SP." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/saml/parse-sp-metadata", summary: "Turn SP metadata (upload or `https` URL) into a draft. Stores nothing; `503` on a server built without SAML." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/saml/idp-credentials", summary: "List the signing credentials, public facts only." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/saml/idp-credentials", summary: "Issue a credential into an empty `active` or `next` slot (`201`)." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/promote", summary: "Make the `next` credential `active`; retire and destroy the old one." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/retire", summary: "Retire a `next` or `active` credential and destroy its key." },
        ],
      },
      {
        type: "p",
        text: "Three permissions, seeded per tenant: `saml_sp:read`, `saml_sp:write` and `saml_idp:credential`. Only a human administrator may call these — a service-account token is refused with `401` — and only for the caller's own tenant. Changes write `saml_sp.created`, `saml_sp.updated`, `saml_sp.deleted`, `saml_sp.metadata_parsed`, `saml_idp.credential_issued`, `saml_idp.credential_promoted` and `saml_idp.credential_retired` audit rows that name ids, changed fields and fingerprints and never a certificate or a document. Sign-ons and logouts are audited too, without the `NameID`.",
      },
      {
        type: "links",
        links: [
          {
            label: "CONTRACT §29 — SAML service provider registration",
            href: contractLink("29"),
            note: "The normative text for the eleven operations: shapes, every server rule an SDK can observe, error mapping, and the tests an SDK port owes.",
          },
          {
            label: "Design document §8e — SAML 2.0 Identity Provider",
            href: `${GH_BLOB}/claude_dev/design-document.md`,
            note: "Assertion contents, the two-leg sign-on, signing rules and the threat reasoning behind each refusal.",
          },
          {
            label: "Deployment guide — environment variables",
            href: `${GH_BLOB}/docs/deployment/README.md`,
            note: "The operator's side: the pairwise key and the rate-limit variables.",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Federation (SAML & OIDC) →",
            body: "The other direction: trusting an external identity provider instead of being one.",
            to: "docs",
            doc: "federation",
          },
          {
            title: "Settings →",
            body: "Where `saml_idp_enabled` is set, and how organization and tenant values combine.",
            to: "docs",
            doc: "settings",
          },
        ],
      },
    ],
  },

  {
    slug: "ssf",
    section: "APIs & integration",
    navLabel: "Shared Signals (SSF)",
    title: "Shared Signals (SSF) transmitter",
    intro:
      "Tell the applications that trust AXIAM the moment something about a person changes: a session was revoked, a credential was replaced, an account was disabled or erased. AXIAM sends signed security events to the receivers you register, by push or by poll, using the OpenID Shared Signals Framework.",
    blocks: [
      { type: "h", id: "what", text: "What it does" },
      {
        type: "p",
        text: "An access token lives fifteen minutes and a session at a relying party lives as long as that party lets it, so a logout, a disabled account or a replaced passkey at AXIAM does not by itself reach the applications downstream. [Back-channel logout](#/docs/logout) tells an OIDC relying party that one session ended; the [revocation feed](#/docs/oauth2#revocations) lets a resource server notice a revoked session. The Shared Signals Framework (SSF) is the standard channel for the wider set: **AXIAM is the transmitter, and a receiver you register is told what happened**, so it can end its own session, force a new sign-in or lock its own record.",
      },
      {
        type: "list",
        items: [
          "**The specifications.** OpenID Shared Signals Framework 1.0 (final), with the CAEP 1.0 and RISC 1.0 event types, Security Event Tokens (RFC 8417), push delivery (RFC 8935), poll delivery (RFC 8936) and RFC 9493 subject identifiers. Discovery publishes `spec_version` `1_0`.",
          "**Six events.** CAEP `session-revoked`, `credential-change` and `assurance-level-change`, and RISC `account-disabled`, `account-enabled` and `account-purged`. Every SET carries exactly one. Two protocol events ride along: a *verification* event a receiver can ask for, and a *stream-updated* event AXIAM sends when an administrator changes a stream's status.",
          "**Signed with the key you already publish.** Each SET is a JWT signed EdDSA with the deployment's key, found at the tenant's JWKS (`jwks_uri` in the discovery document), the same key that signs ID tokens. There is **one** key per deployment; AXIAM has no per-tenant signing keys. The JOSE `typ` is `secevent+jwt`, which is what stops a SET passing as an access token.",
          "**No `exp`.** SSF forbids it, so a SET never expires. A receiver decides how long a SET is news by its `iat`, and **must de-duplicate on `jti`**: the same event can arrive twice (see [delivery guarantees](#/docs/ssf#guarantees)).",
          "**One tenant, one issuer.** `iss` is the tenant's issuer — `{root}/t/{tenant}` where the deployment serves per-tenant issuers (see [Per-tenant issuers](#/docs/oauth2#tenant-issuers)), the root issuer otherwise — and is identical to the `issuer` in the discovery document.",
          "**Several tenants need per-tenant issuers.** Without per-tenant issuers every tenant's SETs would carry the same `iss` and the same key, and an administrator of one tenant who registered another tenant's receiver audience first could push SETs that receiver accepts. So **a deployment that holds more than one tenant must serve per-tenant issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS`) for SSF to run**: without them SSF is inactive for every tenant, exactly as if `ssf_enabled` were off (see [Switch it on](#/docs/ssf#enable)). A single-tenant deployment keeps the root issuer; nobody else shares it.",
          "**What a receiver should check.** Verify `iss` against the issuer of the tenant you registered with — it is what tells tenants apart — take your `aud` from your own stream (`GET /ssf/v1/stream`) rather than from a convention such as your own URL, and require the push `Authorization` header you supplied. An audience is unique across the deployment, but another tenant can register yours before you do; your own registration then fails with `409`, and the checks above keep its SETs from being accepted as yours.",
        ],
      },
      { type: "h", id: "enable", text: "Switch it on" },
      {
        type: "p",
        text: "The transmitter is off until you turn it on. `ssf_enabled` is a layered setting with the shape of `saml_idp_enabled` (see [Settings](#/docs/settings)): **off by default**, turned on by the organization, and a tenant may only turn it *off* again. Set it through the settings API; the console explains the setting but has no control for it yet.",
      },
      {
        type: "p",
        text: "With the setting off, discovery answers an empty `404`, the receiver's stream API sees no stream at all, and nothing is produced. Registering streams does **not** depend on it, so you can register every receiver first and switch the transmitter on last.",
      },
      {
        type: "warn",
        text: "**More than one tenant: per-tenant issuers first.** While the deployment holds more than one tenant (counted across every organization) and does not serve per-tenant issuers, SSF is **inactive for every tenant**, whatever `ssf_enabled` says: discovery is `404`, receivers see no stream, nothing is produced or signed, a push already queued is dead-lettered and a poll returns nothing. Turning `ssf_enabled` on is refused with `400` naming the cause; the stream registry keeps working, and a stream and the settings API say why SSF is inactive. Set `AXIAM__AUTH__TENANT_ISSUER_PATHS=true` to run SSF. The tenant count is re-read at least once a minute: the instance that creates a second tenant stops SSF at once, other instances within a minute. The change is logged once at `WARN` and audited as `ssf.inactive_shared_issuer` in every tenant with SSF on.",
      },
      {
        type: "table",
        headers: ["Discovery URL", "Where"],
        rows: [
          ["`GET {root}/.well-known/ssf-configuration?tenant_id={tenant}`", "Every deployment."],
          ["`GET {root}/.well-known/ssf-configuration/t/{tenant}`", "Deployments that serve per-tenant issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS`): SSF's insertion form, for the issuer `{root}/t/{tenant}`."],
        ],
      },
      {
        type: "p",
        text: "Discovery is unauthenticated, as SSF requires. An unknown tenant, a malformed id, a tenant whose switch is off and every tenant while SSF is inactive for want of per-tenant issuers all answer the **same empty `404`**, so the route does not tell anyone which tenants exist or transmit. The document lists the supported events, the two delivery methods, the stream, status and verification endpoints, and `default_subjects` of `ALL`.",
      },
      { type: "h", id: "register", text: "Register a receiver (administrator)" },
      {
        type: "p",
        text: "A stream is created by a **tenant administrator**, never by the receiver: deciding which third party receives security events about the tenant's users is a human administrator's act. The registry is a REST API under `/api/v1/tenants/{tenant_id}/ssf/streams` (the `ssf` namespace of the SDKs' management surface). Reading needs `ssf_streams:read` and the three writes need `ssf_streams:write`, both seeded per tenant. A service-account token is refused with `401` and another tenant's id with `403`. The admin console has no page for it yet.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Create the receiver's OAuth2 client",
            body: "An OAuth2 client of the tenant, registered for the `client_credentials` grant with the scope `ssf.manage`. Its `client_id` is the stream's `receiver_client_id`, and the client is how the receiver proves who it is on the stream API below. Any other client is refused with `400` naming what is missing.",
          },
          {
            title: "Register the stream",
            body: "Everything a receiver may not change is decided here: the audience, the delivery method, the subject format and the ceiling of events. A push stream also gets its endpoint and, if the endpoint needs one, an `Authorization` header.",
            code: 'POST /api/v1/tenants/{tenant_id}/ssf/streams\n{\n  "receiver_client_id": "<receiver client id>",\n  "audience": "https://app.example.com/ssf",\n  "delivery_method": "push",\n  "endpoint_url": "https://app.example.com/ssf/events",\n  "authorization_header": "Bearer <receiver token>",\n  "events_allowed": [\n    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",\n    "https://schemas.openid.net/secevent/risc/event-type/account-disabled"\n  ],\n  "subject_format": "iss_sub"\n}',
          },
          {
            title: "Switch the transmitter on",
            body: "Turn `ssf_enabled` on for the tenant. Until then discovery is `404` and the receiver cannot see the stream. On a deployment of several tenants this needs per-tenant issuers first, or it is refused with `400`. Give the receiver its `client_id` and secret, and the discovery URL.",
          },
        ],
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Member", "What it decides"],
        rows: [
          [
            "`audience`",
            "The SET's `aud`, one string. **Unique across the whole deployment**: reusing one, in any tenant, is `409` without saying where. That is what stops one tenant's administrator from registering another tenant's receiver audience to collect events about their own users and replay them where that receiver listens.",
          ],
          [
            "`subject_format`",
            "How a person is named in the stream's SETs. `iss_sub` (the default) is `{iss, sub}` with the `sub` of AXIAM's ID tokens, so a receiver that is also an OIDC relying party can match it. `email` names the person by address, and **only the administrator can choose it**, because it decides what personal data leaves. An address is sent only if AXIAM vouches for it (verified, or the account is active); for any other account the event is **not sent on that stream** — never with `iss_sub` instead.",
          ],
          [
            "`events_allowed`",
            "The ceiling: one to six of the event-type URIs. The receiver may ask for fewer (`events_requested`), never more; `events_delivered` is the intersection.",
          ],
          [
            "`delivery_method`",
            "`push` or `poll`, set here only. A push stream needs `endpoint_url`; a poll stream has none, because AXIAM serves the poll endpoint.",
          ],
          [
            "`endpoint_url`",
            "Held to the webhook outbound address policy: absolute `https`, no credentials or fragment, no non-global IP literal, no `localhost`, `*.local` or `*.internal` name. It is checked again, through the same guard, on every delivery.",
          ],
          [
            "`authorization_header`",
            "The `Authorization` value AXIAM sends with every push. **Write-only**: sealed under `pki_encryption_key` (the key webhook secrets use), never returned (`authorization_header_set` says whether one is stored) and never audited. A deployment without that key refuses a write that stores one with `503`. It **never follows the endpoint to another origin**: moving `endpoint_url` to another scheme, host or port needs the header again, or `clear_authorization_header: true`, else `400`.",
          ],
          [
            "`receiver_client_id`",
            "The OAuth2 client above. It binds the stream to one receiver: only a token for that client sees or changes it.",
          ],
        ],
      },
      {
        type: "p",
        text: "`PUT` is a **replacement**: an omitted optional member takes its default, with one exception — an omitted `authorization_header` keeps the stored one. Read the stream, change what you need and send it back. Every write is audited as `ssf_stream.created`, `ssf_stream.updated` (naming the changed members) or `ssf_stream.deleted`, and never records the header. Deleting a stream removes every event buffered for it.",
      },
      { type: "h", id: "receiver", text: "The receiver's side" },
      {
        type: "p",
        text: "The receiver authenticates with an ordinary OAuth2 **client-credentials** token carrying `ssf.manage`, and calls the stream API under `{root}/ssf/v1/`. A user, service-account or unscoped client token is `403`. A stream bound to another client, another tenant's stream, a stream in a tenant whose switch is off and a stream that does not exist all answer the **same `404`**, so a receiver learns nothing about streams that are not its own.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/ssf/v1/stream", summary: "Read one stream (`?stream_id=`) or every stream bound to the receiver's client." },
          { method: "PATCH", path: "/ssf/v1/stream", summary: "Change the receiver-supplied members that are present." },
          { method: "PUT", path: "/ssf/v1/stream", summary: "Replace them; an omitted receiver member is removed, and `delivery` is required." },
          { method: "GET", path: "/ssf/v1/status", summary: "The stream's status (`?stream_id=`)." },
          { method: "POST", path: "/ssf/v1/status", summary: "Set the stream's status, subject to the rule below." },
          { method: "POST", path: "/ssf/v1/verify", summary: "Ask for a verification event; `204`." },
          { method: "POST", path: "/ssf/v1/poll/{stream_id}", summary: "Poll a poll stream (RFC 8936)." },
        ],
      },
      {
        type: "p",
        text: "`POST` and `DELETE` on `/ssf/v1/stream` are `403`: streams belong to the administrator. These routes are in the OpenAPI document under the `ssf-receiver` tag and are not part of any SDK's management surface.",
      },
      { type: "h", id: "receiver-change", text: "What a receiver may change" },
      {
        type: "table",
        headers: ["The receiver may", "The receiver may not"],
        rows: [
          ["Narrow `events_requested` within `events_allowed` (an unknown URI is ignored; a known one outside the ceiling is `400`)", "Change the delivery method, the audience, the subject format or `events_allowed`"],
          ["Change `description`", "Create or delete a stream"],
          ["On a push stream, change `endpoint_url` (same address policy, same origin rule) and supply `authorization_header`", "Read a stored `authorization_header`"],
          ["Set the stream's status, unless an administrator has stopped it (below)", "Restart a stream an administrator paused or disabled (`403`)"],
        ],
      },
      { type: "h", id: "status", text: "Statuses" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Status", "What happens to an event"],
        rows: [
          ["`enabled`", "Signed and transmitted."],
          ["`paused`", "Nothing is signed or transmitted. The event is **held** in the stream's buffer and sent, oldest first, when the stream is enabled again."],
          ["`disabled`", "Nothing is signed, transmitted or held. An event for it is dropped where it is produced, one already queued is dead-lettered, and verification is `400`."],
        ],
      },
      {
        type: "p",
        text: "An administrator may set any status. The receiver may set any status **unless an administrator set the current one to something other than `enabled`**: a receiver cannot restart what an administrator stopped. An administrator's status change is announced to the receiver with a stream-updated event (`{status, reason?}`) once the change is written; a receiver's own change is not announced, as SSF says. A SET is signed only against the stream as it is at that moment, so a stream disabled, paused or narrowed after an event was queued delivers nothing.",
      },
      { type: "h", id: "verify", text: "Verification" },
      {
        type: "p",
        text: "`POST /ssf/v1/verify` with `{ \"stream_id\": …, \"state\": … }` (`state` is optional, at most 1 KiB) asks AXIAM to send the stream a verification event carrying that `state`, so a receiver can prove its endpoint and key handling end to end. It answers `204` and the event follows through the stream's own delivery. **At most one request every 60 seconds per stream** (`min_verification_interval`; `429` inside it, enforced in the datastore so it holds across replicas), and `400` for a disabled stream. A paused stream holds the verification event like any other.",
      },
      { type: "h", id: "poll", text: "Poll delivery" },
      {
        type: "p",
        text: "For a poll stream the receiver asks for events at `POST {root}/ssf/v1/poll/{stream_id}` with its token. The body is RFC 8936's, every member optional; a `400` answers a push stream.",
      },
      {
        type: "code",
        caption: "POST /ssf/v1/poll/{stream_id}",
        code: '{\n  "maxEvents": 25,\n  "returnImmediately": false,\n  "ack": ["<jti of an event the receiver processed>"],\n  "setErrs": { "<jti>": { "err": "invalid_request", "description": "…" } }\n}\n\n// 200\n{ "sets": { "<jti>": "<compact SET>" }, "moreAvailable": false }',
      },
      {
        type: "list",
        items: [
          "**`maxEvents`** is clamped to 100 (a missing value means 100; a negative one is `400`; `0` means acknowledgements only). Events come **oldest first**.",
          "**Long poll.** Unless the request sets `returnImmediately: true` it waits up to **30 seconds** for an event. AXIAM allows **one waiting long poll per stream** (per server instance): a second concurrent request on the same stream is answered at once, as if it had set `returnImmediately`. A receiver that runs several pollers on one stream gets a busy loop from the extras, not more throughput.",
          "**`ack`** deletes exactly the events it names, in this stream and no other. Anything not acknowledged is returned again by the next poll, which is what makes delivery at-least-once. At most 1 000 `ack` and 100 `setErrs` entries per request, and the body is at most 32 KiB (`413`).",
          "**`setErrs`** reports a SET the receiver could not accept (an RFC 8935 `err` code). AXIAM deletes that event, so it is not offered again, and writes an audit row with the code. The receiver's `description` text is never stored.",
          "**A paused or disabled stream** answers an empty `sets`. The poll response is `Cache-Control: no-store`.",
        ],
      },
      { type: "h", id: "push", text: "Push delivery" },
      {
        type: "p",
        text: "For a push stream AXIAM `POST`s each SET to the endpoint (RFC 8935) with `Content-Type: application/secevent+jwt`, `Accept: application/json`, the stored `Authorization` header if there is one, and a 10-second timeout. **Redirects are never followed**: a `3xx` is a failed attempt, so the endpoint, and the credential sent to it, cannot be rerouted by the receiver's own server. At most 64 KiB of the response is read, and it is never logged.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["The receiver answers", "AXIAM"],
        rows: [
          ["`202`, or any `2xx`", "Delivered."],
          ["`400` with an RFC 8935 `err` code", "Dead-lettered: the SET will not be accepted on retry. The code goes into the audit row."],
          ["`401`, `403`", "Dead-lettered: the credential is wrong until someone fixes it."],
          ["Any other `4xx` (a `400` with no known code, `410`, `422`, …)", "Dead-lettered, with the reason `HTTP <status>`."],
          ["`404`, `408`, `429`, `5xx`, a timeout, no connection, a `3xx`", "Retried on the schedule below."],
        ],
      },
      {
        type: "p",
        text: "A stream that is gone or disabled when the attempt runs is dead-lettered; one that is paused moves the event to the buffer and the message is acknowledged. **Resuming** a paused push stream sends its held events, oldest first. The audit reasons come from a fixed vocabulary and never contain a header, a URL, a response body or a transport error's text.",
      },
      { type: "h", id: "triggers", text: "What triggers each event" },
      {
        type: "p",
        text: "Events are produced at the place where the change happens, for every stream that carries that event type, and only while `ssf_enabled` is on and SSF is active (see [Switch it on](#/docs/ssf#enable)). A cause that produces several events (a password reset's `credential-change` and `session-revoked`) shares one `txn` value.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Event", "Sent when", "Not sent when"],
        rows: [
          [
            "`session-revoked`",
            "A session is ended by logout, by an administrator, or by policy. One SET per session id, naming the session as well as the person.",
            "A session simply **expires**; a refresh token is revoked (RFC 7009), which is not a session revocation; a token is redeemed. It does not depend on `revocation_feed_enabled`.",
          ],
          [
            "`credential-change`",
            "A password is changed or reset, a SCIM password write, an OPAQUE registration, an authenticator app (TOTP) confirmed, MFA reset or a method deleted, a passkey (`fido2-platform`) or security key (`fido2-roaming`) registered or deleted.",
            "Never for `x509`: the event shape exists, but certificates bind only to service accounts and an SSF subject is a user, so nothing emits it.",
          ],
          [
            "`assurance-level-change`",
            "A **step-up** re-authentication completes and the new session's `acr` differs from the one it replaces (`urn:axiam:acr:1fa` and `urn:axiam:acr:mfa`); it carries both levels and the direction.",
            "A sign-in that is not a step-up, a step-up that lands on the same `acr`, or one that returns for another user or after the ten-minute window.",
          ],
          [
            "`account-disabled`",
            "A user becomes inactive through the admin API or SCIM (`active: false`), or a directory sync deactivates the account.",
            "A **lockout** is not a disable.",
          ],
          [
            "`account-enabled`",
            "The reverse, through the admin API or SCIM (`active: true`).",
            "A directory sync never re-enables an account, so it never produces this event.",
          ],
          [
            "`account-purged`",
            "A user is deleted through the admin API or SCIM `DELETE`, or erased under GDPR. The subject is captured before the write, because the person no longer exists at delivery.",
            "—",
          ],
        ],
      },
      {
        type: "note",
        text: "Production is best effort, as for webhooks: failing to queue an event does not fail the operation that caused it. A receiver that needs certainty about one account can read the account's current state from AXIAM after a signal; the signal says *something changed*, never the only record of it.",
      },
      { type: "h", id: "guarantees", text: "Delivery guarantees and limits" },
      {
        type: "list",
        items: [
          "**At-least-once.** A push that was not acknowledged is retried; a polled event stays until acknowledged. A retried push or repeated poll carries the **byte-identical SET with the same `jti`** (Ed25519 is deterministic), so de-duplicating on `jti` is exact. Keep the `jti`s you processed for at least seven days, and record a `jti` only after the SET verified.",
          "**The buffer.** Held events — a poll stream's, and any paused stream's — are kept at most **1 000 per stream**; when it is full the **oldest is dropped** to admit the newest, because the newest state is the one a receiver can act on. An event is also kept for **seven days at most**, then swept.",
          "**The dead-letter queue.** An event that exhausted its attempts or can never be accepted lands in `axiam.ssf_push.dlq`, whose messages expire after **seven days**. They hold unsigned subjects, possibly an address, so they are not kept longer. The webhook queue is a separate one with its own lifetime.",
          "**Retries.** Push uses the same retry machinery as webhooks, tuned by `AXIAM__SSF_PUSH__MAX_ATTEMPTS` (default 5, counting the first attempt), `AXIAM__SSF_PUSH__BACKOFF_BASE_MS` (default 5 000) and `AXIAM__SSF_PUSH__BACKOFF_CEILING_MS` (default 3 600 000). See [Configuration](#/docs/configuration).",
          "**Rate limits.** Each receiver route and each discovery form has its own per-IP bucket, `AXIAM__RATE_LIMIT__SSF_PER_MIN` (default 60 a minute); an honest long-polling receiver makes about two requests a minute. The registry's three writes have one bucket per route under `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN` (default 30); reads are not limited. Neither moves with `AXIAM__RATE_LIMIT__PROFILE`.",
        ],
      },
      { type: "h", id: "privacy", text: "Privacy" },
      {
        type: "list",
        items: [
          "**No free text a person typed is ever sent.** CAEP's `reason_admin`, `reason_user` and `friendly_name` members are never populated, and no event member carries a name, a description or a message. A receiver gets URIs, enumerations and timestamps.",
          "**The subject is resolved when the event is produced, per stream**, not at delivery: an erased account no longer exists by then. The consequence is that an event for an `account-purged` user can sit in a buffer, naming that user, for up to the seven-day bound above.",
          "**What leaves is the administrator's decision.** The subject format, the event ceiling and the endpoint are all set at registration, and a receiver can only narrow what it gets.",
        ],
      },
      { type: "h", id: "unsupported", text: "What it does not do" },
      {
        type: "list",
        items: [
          "**Add and remove subject.** AXIAM advertises `default_subjects: ALL` and publishes no add-subject or remove-subject endpoint. A stream carries every user of the tenant; a receiver cannot ask for one person's events only.",
          "**Receiver-created streams.** A third party choosing which personal data it receives is the administrator's decision, so `POST` and `DELETE` on the stream endpoint are `403`.",
          "**Per-tenant signing keys.** One deployment key signs every SET and is published at each tenant's JWKS. Rotating it is the deployment's key rotation, and every receiver reads it from the JWKS.",
          "**A SET that expires.** There is no `exp` and no `sub` claim, by specification and on purpose.",
          "**Certificate events.** `x509` credential changes are never sent today (see the table above).",
          "**An `ssf` control in the console.** Registration is through the REST API and the SDKs' `ssf` management namespace.",
        ],
      },
      { type: "h", id: "sdks", text: "From the SDKs" },
      {
        type: "p",
        text: "The registry is the SDKs' `ssf` management namespace (five operations; the `authorization_header` is a `Sensitive` value in every SDK). Verifying a SET and polling are the **optional receiver helper** of the Rust, TypeScript, Python, Java, C#, PHP and Go SDKs: it verifies the signature against the JWKS, checks `typ`, `alg`, `aud` and `iss`, and de-duplicates the `jti`. An SDK never transmits. The SDK ports follow the server's release; until they ship, verify a SET with any JWT library, applying the same checks, and de-duplicate on `jti` yourself.",
      },
      { type: "h", id: "api", text: "Management endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/ssf/streams", summary: "List registered streams (paged, searchable by audience, receiver client, description or id)." },
          { method: "POST", path: "/api/v1/tenants/{tenant_id}/ssf/streams", summary: "Register one (`201`)." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}", summary: "Read one. The `Authorization` header is never returned." },
          { method: "PUT", path: "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}", summary: "Replace it. An omitted `authorization_header` keeps the stored one." },
          { method: "DELETE", path: "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}", summary: "Delete it and every event buffered for it (`204`)." },
          { method: "GET", path: "/.well-known/ssf-configuration", summary: "Transmitter metadata (`?tenant_id=`). Empty `404` when off.", public: true },
          { method: "GET", path: "/.well-known/ssf-configuration/t/{tenant_id}", summary: "The same, in the per-tenant issuer form.", public: true },
        ],
      },
      {
        type: "links",
        links: [
          {
            label: "CONTRACT §32 — SSF stream registration and the receiver helper",
            href: contractLink("32"),
            note: "The normative text: the registry operations and shapes, every server rule an SDK can observe, the receiver protocol, the SET, the receiver helper and the tests an SDK port owes.",
          },
          {
            label: "Design document — competitor gap remediation, item G-5 and decisions D-44 … D-53",
            href: `${GH_BLOB}/claude_dev/competitor-gap-remediation-plan-2026-10-02.md`,
            note: "Why each choice was made: the SET shape, the audience rule, the subject policy, the status model and the event sources.",
          },
          {
            label: "Deployment guide — environment variables",
            href: `${GH_BLOB}/docs/deployment/README.md`,
            note: "The operator's side: the rate-limit and retry variables.",
          },
        ],
      },
      {
        type: "cards",
        cards: [
          {
            title: "Logout & sessions →",
            body: "Back-channel logout: telling an OIDC relying party that one session ended.",
            to: "docs",
            doc: "logout",
          },
          {
            title: "Settings →",
            body: "Where `ssf_enabled` is set, and how organization and tenant values combine.",
            to: "docs",
            doc: "settings",
          },
          {
            title: "Webhooks →",
            body: "The other outbound channel: HMAC-signed JSON events, on the same delivery machinery.",
            to: "docs",
            doc: "webhooks",
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
        text: "Every attempt goes through the same SSRF guard the federation client uses: the host is resolved fresh, a private, loopback or link-local address is refused, the validated IP is pinned into the connection so nothing can re-resolve between the check and the send, and a non-HTTPS target is treated as blocked. The shared secret is stored AES-256-GCM encrypted under `AXIAM__AUTH__PKI_ENCRYPTION_KEY`, is never returned by any endpoint, and is decrypted in memory only to compute a signature — with no key configured the subsystem fails closed with a `503` rather than delivering unsigned.",
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
        type: "p",
        text: "Shared Signals Framework push delivery runs on the same dispatcher with queues of its own (`axiam.ssf_push`, `.retry`, `.dlq`) and the same schedule, read from the kind's own variables so tuning one never moves the other. Its dead-letter queue discards a message after seven days, because a dead-lettered event still names a person.",
      },
      {
        type: "table",
        headers: ["Config key", "Default", "Meaning"],
        rows: [
          [
            "AXIAM__SSF_PUSH__MAX_ATTEMPTS",
            "`5`",
            "Total push attempts per event before it is dead-lettered; the first attempt counts as one.",
          ],
          [
            "AXIAM__SSF_PUSH__BACKOFF_BASE_MS",
            "`5000`",
            "Delay before the first retry of a push.",
          ],
          [
            "AXIAM__SSF_PUSH__BACKOFF_CEILING_MS",
            "`3600000`",
            "Upper bound on any single push retry delay — one hour.",
          ],
        ],
      },
      {
        type: "p",
        text: "Outbound SCIM provisioning (AXIAM pushing users and groups to a downstream SCIM 2.0 service provider) is the third kind on the dispatcher, with queues of its own (`axiam.scim_push`, `.retry`, `.dlq`) and its own variables. A queued message holds only the id of the user or group to re-sync, never an attribute of a person; the dead-letter queue still discards after seven days, because the ids are user ids.",
      },
      {
        type: "table",
        headers: ["Config key", "Default", "Meaning"],
        rows: [
          [
            "AXIAM__SCIM_PUSH__MAX_ATTEMPTS",
            "`5`",
            "Total attempts per provisioning message before it is dead-lettered; the first attempt counts as one.",
          ],
          [
            "AXIAM__SCIM_PUSH__BACKOFF_BASE_MS",
            "`5000`",
            "Delay before the first retry of a provisioning message.",
          ],
          [
            "AXIAM__SCIM_PUSH__BACKOFF_CEILING_MS",
            "`3600000`",
            "Upper bound on any single provisioning retry delay — one hour.",
          ],
        ],
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
          ["503 with slug `write_contention`", "NetworkError", "**Retryable.** A write lost an optimistic-concurrency race and stayed lost after every retry the server would spend. Carries `Retry-After: 1`."],
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
          ["RESOURCE_EXHAUSTED (8)", "NetworkError", "Rate-limited — *you sent too much*, and deliberately distinct from UNAVAILABLE."],
        ],
      },
      { type: "h", id: "write-contention", text: "`503 write_contention` — why not `409`, and why not `500`" },
      {
        type: "p",
        text: "All three are plausible answers to a write that lost a datastore race, and the choice is worth stating. A `409` in SCIM means *your request conflicts with the resource's state* (RFC 7644 §3.12) — a statement about the **request**, which a caller correctly answers by changing it; that cannot help here, because the request was fine and lost a race. A `500` tells a client to stop, which is exactly the wrong advice: an identity provider driving SCIM provisioning reads it as a failed sync and re-sends the whole record. `503` with `Retry-After` says the true thing — *come back in a moment* — and is what Okta- and Entra-shaped provisioning already retries.",
      },
      {
        type: "list",
        items: [
          "**`Retry-After: 1` is a convention, not a measurement.** The server does not know how long contention will last, and a fabricated number would be worse than a conventional one. Every SDK honours it as a **floor** and never a ceiling (contract §16.1), so your own backoff still governs the wait.",
          "**A contended `PATCH` is not auto-retried.** Contract §16.2 makes only side-effect-free operations eligible for automatic retry; the caller owns that decision.",
          "**Over gRPC the same condition is `UNAVAILABLE` (14)**, which lands in `NetworkError` exactly as the REST `503` does — and stays distinct from `RESOURCE_EXHAUSTED` (8), because *the server is busy* and *you sent too much* are different instructions.",
        ],
      },
      { type: "h", id: "device-login", text: "Device login — `POST /api/v1/auth/device`" },
      {
        type: "table",
        headers: ["Status", "Type", "When"],
        rows: [
          ["401", "AuthError", "Every certificate refusal: unknown, untrusted, self-asserted, and — since `1.0.0-beta17` — bound to no service account. The bodies are distinct messages; read the body to tell them apart."],
          ["429", "NetworkError", "Over `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN` (default 60 per IP, machine family). Body `rate_limit_exceeded`, with `Retry-After`."],
        ],
      },
      {
        type: "p",
        text: "**Correction.** The `403` on this route is gone. Before `1.0.0-beta17` a certificate bound to no principal answered `403`, and reached that status by matching the text of an error message raised in a lower crate. A `403` asserts an identity and then refuses what it may do; a certificate bound to no principal identifies nobody, which is what its three sibling refusals already said with `401`. Nothing is newly disclosed — the bodies were always distinct, and a test pins them. A client that mapped `403` on this endpoint to *bound, but not permitted* should map `401` and read the body.",
      },
      {
        type: "note",
        text: "The route carried no rate limiter at all before `1.0.0-beta17`. It is public and CSRF-exempt, as it has to be — a device has no session and no cookie — and a device re-authenticates once per access-token lifetime, so the default holds nine hundred devices on one address; `AXIAM__RATE_LIMIT__PROFILE` scales it for a fleet behind a single NAT. See [Configuration](#/docs/configuration#rate-limit).",
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
      { type: "h", id: "oauth2-codes", text: "OAuth2 protocol errors" },
      {
        type: "list",
        items: [
          "**`error_description` is `NQSCHAR`** (RFC 6749 §5.2): ASCII only. A `§` is transliterated to the word *section* rather than silently stripped, so a description is never truncated at its first non-ASCII byte and never carries a byte the grammar forbids.",
          "**`invalid_dpop_proof` (400)** is now the answer where a missing or unverifiable DPoP proof used to produce `invalid_client` (401). The proof is a property of the request, not of the client's identity.",
          "**`login_required`, `consent_required`, `interaction_required`, `account_selection_required`, `unmet_authentication_requirements`** — the answers a client on the [authentication-request honour lane](#/docs/oauth2) can now receive. On the `ignore` lane none of them can occur.",
          "**`invalid_request_uri`** — a pushed `request_uri` that expired, was already consumed, or does not exist. **`request_not_supported`** and **`request_uri_not_supported`** — a request object, and a non-PAR `request_uri`: rejected rather than half-implemented.",
        ],
      },
      {
        type: "note",
        text: "Authorization errors reach the relying party **by redirect**, with `state` and `iss`, whenever the client and `redirect_uri` are registered; a page is rendered only on an explicit `Accept: text/html`, and it echoes nothing the request carried.",
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
