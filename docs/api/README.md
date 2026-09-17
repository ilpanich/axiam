# AXIAM API Documentation

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

AXIAM exposes three API protocols. This page is the single landing point for
all three contract specs and how to view them.

| Protocol | Use case | Spec |
|---|---|---|
| REST | Admin UI, external HTTP integrators | [`openapi.json`](./openapi.json) |
| gRPC | Low-latency service-mesh authz/token/user checks | [`grpc.md`](./grpc.md) → `proto/axiam/v1/*.proto` |
| AMQP | Async authz, audit ingestion, mail, webhook, notification delivery | [`asyncapi.yml`](./asyncapi.yml) |

## REST — OpenAPI

[`openapi.json`](./openapi.json) is a symlink to
[`../../sdks/openapi.json`](../../sdks/openapi.json) — **not a second copy**.
That file is generated from the `utoipa` `ApiDoc` aggregator
(`crates/axiam-api-rest/src/openapi.rs`) and is drift-gated in CI by
[`.github/workflows/sdk-openapi-drift.yml`](../../.github/workflows/sdk-openapi-drift.yml),
which fails any PR where the committed spec diverges from a fresh
`--dump-openapi` export. Publishing it here as a symlink means there is
exactly one source of truth (D-09/D-10) — this page never needs its own
regeneration step.

**Viewing it:** open the JSON in any external Swagger/Redoc viewer, e.g.:

```bash
npx @redocly/cli preview-docs docs/api/openapi.json
```

or paste it into [Swagger Editor](https://editor.swagger.io/). AXIAM does
**not** wire an in-app Swagger UI route (D-10) — this avoids the
`utoipa-swagger-ui` GitHub-egress build fragility documented in
[`CLAUDE.md`](../../CLAUDE.md).

**Regenerating** `sdks/openapi.json` (only needed if you're updating the
REST API itself, not for viewing):

```bash
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > sdks/openapi.json
```

## Errors

Every REST error carries the same JSON envelope, whatever endpoint produced
it — `{ "error": "<slug>", "message": "<sentence>" }`, plus `action` and
`resource_id` on an authorization denial (SDK-Q02). The slug is the stable
part; the message is for a human and may be reworded.

5xx messages are deliberately generic. Internal detail — datastore strings,
crypto messages, anything derived from a secret — never reaches a response
body (SEC-011/SEC-039/CQ-B33), so a `500` says only that an internal error
occurred and the detail is in the server log.

| Status | Slug | Meaning | Retry? |
|---|---|---|---|
| 400 | `validation_error`, `tenant_context`, `email_config_error` | The request is wrong. Resending it unchanged will fail identically | No |
| 401 | `authentication_failed` | Unauthenticated, or the credential was refused | No — refresh, then retry once (CONTRACT §9) |
| 403 | `authorization_denied` | Authenticated, and not permitted. Carries `action` and `resource_id` when known | No |
| 404 | `not_found` | No such resource in this tenant | No |
| 409 | `already_exists` | A uniqueness constraint refused the write | No |
| 409 | `conflict` | The resource is not in a state that permits this. The caller must do something else first, not resend | No |
| 422 | `password_policy_violation` | The password was rejected by policy | No |
| 429 | `rate_limited` | Over a rate limit. Carries `Retry-After` | Yes, after the header's delay |
| 503 | `service_unavailable` | A capacity gate refused the request — most often the Argon2id hash gate under load | Yes |
| 503 | `write_contention` | A write lost an optimistic-concurrency race in the datastore and stayed lost after every retry the server was willing to spend. Carries `Retry-After: 1` | **Yes** |
| 500 | `internal_error` | Everything else. The detail is in the server log | No |

**On `write_contention` (T-262).** It answers `503` rather than `409` or `500`
deliberately, and the distinction is worth stating because all three are
plausible. A `409` in SCIM means "your request conflicts with the resource's
state" (RFC 7644 §3.12) — a statement about the *request*, which a caller
correctly responds to by changing it; that cannot help here, because the
request was fine and lost a race. A `500` tells a client to stop, which is
exactly wrong advice: an IdP driving SCIM provisioning reads it as a failed
sync and re-sends the whole record. `503` with `Retry-After` says the true
thing — come back in a moment — and is what Okta- and Entra-shaped
provisioning already retries.

The `Retry-After: 1` is a convention, not a measurement: the server does not
know how long contention will last, and a fabricated number would be worse
than a conventional one. Every AXIAM SDK honours it as a **floor** and never a
ceiling (CONTRACT §16.1), so a client's own backoff still governs the wait.
Note that §16.2 makes only side-effect-free operations eligible for automatic
retry — a contended `PATCH` is *not* retried by the SDK, and the caller owns
that decision.

Over gRPC the same condition is `UNAVAILABLE` (14), which CONTRACT §2 maps to
`NetworkError` — the same place the REST `503` lands. It stays distinct from
`RESOURCE_EXHAUSTED` (8), which is this listener's rate-limit answer: "the
server is busy" and "you sent too much" are different instructions.

## gRPC

See [`grpc.md`](./grpc.md) for the service summary and how to consume the
API. The `.proto` files themselves live in
[`proto/axiam/v1/`](../../proto/axiam/v1/) and are the source of truth —
`grpc.md` references them by path rather than duplicating their contents.

## Discovery — OIDC and RFC 8414

`GET /.well-known/openid-configuration` returns the OpenID Provider metadata
document (OIDC Discovery 1.0 §3). The same document, built by the same
handler, is also served at `GET /.well-known/oauth-authorization-server`
(RFC 8414 §3) — a second conventional path some clients probe first and never
fall back from, most notably [MCP](https://modelcontextprotocol.io) clients
per the [MCP authorization
specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
Both accept the same optional `?tenant_id=` query parameter (X7 G8) and are
otherwise identical: same JSON body, same `Cache-Control` and `Content-Type`
headers, same tenant-scoped `sensitive_scopes_enabled` behaviour. There is one
discovery document; the second path is an alias, not a second implementation.

```bash
curl -s https://axiam.example.com/.well-known/oauth-authorization-server
curl -s "https://axiam.example.com/.well-known/oauth-authorization-server?tenant_id=$TENANT_ID"
```

## OAuth2 public clients

A client that cannot keep a secret — a desktop or CLI application, a
single-page application, a mobile app — registers with
`token_endpoint_auth_method: "none"` and authenticates with PKCE instead. When
to do that, what such a registration is refused, and the RFC 8252 §7.3
ephemeral-port rule for `http://127.0.0.1`, `http://[::1]` and
`http://localhost` callbacks are in
[`../admin/public-clients.md`](../admin/public-clients.md).

## OAuth2 device flow

Input-constrained clients (televisions, CLIs, headless commissioning) use the
Device Authorization Grant. Endpoints, the polling answer table, the
verification page's API, and the rate-limit reasoning are in
[`device-flow.md`](device-flow.md).

## OAuth2 token exchange

Services that hold a user's token and need a narrower one to call a second
service use the Token Exchange grant (RFC 8693). Delegation vs impersonation,
the scope-narrowing rule, the lifetime cap and the error table are in
[`token-exchange.md`](token-exchange.md).

## UMA 2.0 — Protection API and ticket grant

A service that guards resources it does not own registers them, asks AXIAM what
a caller would need, and exchanges the resulting permission ticket for a
Requesting Party Token. What maps onto what, the ticket lifecycle, the
`WWW-Authenticate: UMA` challenge, and the single-use limitation are in
[`uma.md`](uma.md).

## SCIM 2.0 provisioning

An IdP (Okta, Entra ID) creates, updates, and deactivates AXIAM users and
groups directly via `/scim/v2`. Endpoint list, the filtering/PATCH subset,
how tenant scoping is enforced, and Okta + Entra setup walkthroughs are in
[`scim-provisioning.md`](scim-provisioning.md).

## Logout — RP-initiated and back-channel

Ending a session at AXIAM and telling every relying party that shared it.
The redirect allow-list, why an unverifiable `id_token_hint` ends nothing,
the logout-token shape and the delivery model are in
[`logout.md`](logout.md).

## AMQP — AsyncAPI

[`asyncapi.yml`](./asyncapi.yml) is an AsyncAPI 2.6 document describing
every AMQP queue and message type AXIAM publishes/consumes (authz
request/response, audit events, notifications, outbound mail, webhook
delivery + its DLQ/retry chain).

**Important — this is a hand-authored snapshot, not a generated artifact.**
Unlike the REST OpenAPI spec, there is no codegen link between
`asyncapi.yml` and `crates/axiam-amqp/src/messages.rs` (D-07 chose
hand-authoring for AMQP; REST/gRPC are generated/referenced instead). It
was transcribed field-for-field from `messages.rs` and
`connection.rs::queues` as of this milestone's `Last verified` date above.
**If `messages.rs` or `connection.rs` change, `asyncapi.yml` must be
manually re-verified and updated** — no CI drift gate catches divergence
between the spec and the Rust structs (only the spec's own JSON-Schema
validity is checked).

**Viewing it:** any AsyncAPI-compatible viewer works, e.g. the
[AsyncAPI Studio](https://studio.asyncapi.com/) (paste the file contents),
or validate it locally:

```bash
npx @asyncapi/cli validate docs/api/asyncapi.yml
```

**Validation is local-only (not CI-enforced yet).** The docs CI job
([`.github/workflows/docs-ci.yml`](../../.github/workflows/docs-ci.yml))
enforces the internal link-check and the OpenAPI JSON parse-check, but
**intentionally omits** the AsyncAPI meta-schema validation step above. The
`@asyncapi/cli` package returned a `[SUS]` verdict from this project's
automated Package Legitimacy Audit — a sandbox download-telemetry gap, not a
genuine trust concern (`@asyncapi/cli` is the official AsyncAPI Initiative CLI,
[github.com/asyncapi/cli](https://github.com/asyncapi/cli)). Rather than
autonomously add a SUS-flagged supply-chain dependency to CI, the AsyncAPI half
falls back to running the command above **locally before commit**. A maintainer
may wire the step into `docs-ci.yml` after confirming the package at
[npmjs.com/package/@asyncapi/cli](https://www.npmjs.com/package/@asyncapi/cli).

## See also

- [`docs/README.md`](../README.md) — top-level documentation index
- [`docs/deployment/README.md`](../deployment/README.md) — required env vars, secrets, NetworkPolicies
- [`../../sdks/CONTRACT.md`](../../sdks/CONTRACT.md) — the cross-language SDK contract (the SDKs themselves live in the `ilpanich/axiam-<lang>-sdk` repositories)
- [`../../claude_dev/security-audit.md`](../../claude_dev/security-audit.md) — security/compliance master document
