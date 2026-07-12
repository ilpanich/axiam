# AXIAM gRPC API

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

Low-latency gRPC surface for service-mesh authorization checks, JWT
validation/introspection, and user lookups. Backed by [Tonic](https://github.com/hyperium/tonic)
server-side (`crates/axiam-api-grpc`) and generated client stubs across
every SDK language via [buf](https://buf.build).

This guide references the `.proto` files by path rather than transcribing
them — the `.proto` files are the source of truth; regenerate stubs (below)
rather than hand-editing generated code.

## Services

| Proto file | Service | RPCs |
|---|---|---|
| [`proto/axiam/v1/authorization.proto`](../../proto/axiam/v1/authorization.proto) | `AuthorizationService` | `CheckAccess` (single access check), `BatchCheckAccess` (multiple checks in one round-trip) |
| [`proto/axiam/v1/token.proto`](../../proto/axiam/v1/token.proto) | `TokenService` | `ValidateToken` (signature + expiry), `IntrospectToken` (RFC 7662-style full claims) |
| [`proto/axiam/v1/user.proto`](../../proto/axiam/v1/user.proto) | `UserService` | `GetUser` (lookup by ID), `ValidateCredentials` (username/email + password check, no token issued) |

All request/response messages are tenant-scoped (`tenant_id` on every
request) — see each `.proto` file for exact field lists and comments.

## Server

The gRPC server is started by `axiam-server` alongside the REST/AMQP
listeners (`crates/axiam-api-grpc::start_grpc_server`, wired in
`crates/axiam-server/src/main.rs`). It binds to `127.0.0.1:50051` by
default (`GrpcConfig`, `crates/axiam-api-grpc/src/config.rs`) — loopback
only unless explicitly reconfigured behind mTLS or an internal network.
Configure via the `AXIAM__GRPC__*` env vars (see
[`docs/deployment/README.md`](../deployment/README.md) for the full
deployment env-var reference).

## Consuming the API

Client stubs are pre-generated and committed per SDK; you do not need to
run codegen yourself to consume the API from a supported SDK language.
Each SDK lives in its own repository (`ilpanich/axiam-<lang>-sdk`), vendors a
copy of `proto/` from here, and owns its codegen step — `buf generate` for
Rust/TypeScript/Go, and language-specific tooling for Python (grpc_tools),
Java (protobuf-maven-plugin) and C#/PHP (protoc); see each SDK's `buf.gen.yaml`
or build file.
The [`sdk-buf-gates.yml`](../../.github/workflows/sdk-buf-gates.yml) CI job
runs `buf lint` + `buf breaking` against `proto/` on every change, so the
`.proto` contracts are guarded against accidental breaking changes at the
source.

- **Rust:** `axiam-sdk`'s `grpc` feature exposes `AuthzGrpcClient` (see
  the [Rust SDK](https://github.com/ilpanich/axiam-rust-sdk)) — a shared,
  lazily-connected `tonic::Channel` client for `check_access`/`batch_check`.
- **Other languages:** each SDK's own README documents its gRPC client
  surface; all share the same `.proto` contract above.

If you are integrating from a language without a published AXIAM SDK,
generate your own stubs directly from the `.proto` files with `buf generate`
(or `protoc` + your language's gRPC plugin) — the files are
self-contained (proto3, no external imports beyond well-known types).
