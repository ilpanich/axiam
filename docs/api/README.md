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

## gRPC

See [`grpc.md`](./grpc.md) for the service summary and how to consume the
API. The `.proto` files themselves live in
[`proto/axiam/v1/`](../../proto/axiam/v1/) and are the source of truth —
`grpc.md` references them by path rather than duplicating their contents.

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
