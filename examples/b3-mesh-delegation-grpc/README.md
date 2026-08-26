# B3 — mesh-delegation, end to end onto gRPC

**What this demonstrates.** The scenario `docs/api/token-exchange.md` opens
with: *"A service in a mesh receives a request carrying a user's access
token [and] should present a token that is narrower than the one it
holds."* This example plays out both halves — the OAuth2 Token Exchange
(RFC 8693) **delegation** that produces the narrower token, and the
low-latency `axiam.v1.AuthorizationService/CheckAccess` gRPC call the
narrower token is then used for, which is the whole reason Track B's token
exchange exists (`claude_dev/improvement-after-run5-benchmark.md` §B3: "it
complements AXIAM's gRPC data-plane story").

It is also the example
[`docs/api/token-exchange.md`](../../docs/api/token-exchange.md) itself
links to for a worked gRPC integration — see that file's "See also" section.

Rust, matching the rest of this crate's gRPC surface (`crates/axiam-api-grpc`,
`proto/axiam/v1/authorization.proto`) and the `tonic`/`prost` toolchain the
main server already uses; a TypeScript or Go reader will find the wire
shapes identical, just spelled through a different gRPC client library.

## What it does, step by step

1. Admin sets up fixtures: a resource, a permission, a role granting it, and
   a disposable end user assigned that role.
2. Admin registers **two** OAuth2 clients: `storefront-app` (the user-facing
   app the caller logs into — `authorization_code` + `refresh_token`) and
   `orders-mesh-gateway` (the mesh service that will perform the exchange —
   `client_credentials` + `urn:ietf:params:oauth:grant-type:token-exchange`).
3. The end user logs in (a cookie session standing in for a browser) and
   completes a real `authorization_code` + PKCE flow against
   `storefront-app`, ending up with an access token scoped to `orders:read`
   — this is the "inbound request carrying a user's access token."
4. The mesh gateway mints its own `client_credentials` token (the
   `actor_token`).
5. The mesh gateway exchanges the user's token for a narrower one:
   `POST /oauth2/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
   `subject_token=<the user's token>`, `actor_token=<the gateway's own
   token>`. Because `actor_token` is present this is **delegation**, not
   impersonation: the issued token keeps `sub` = the user and gains an `act`
   claim naming the gateway.
6. The gateway calls `AuthorizationService/CheckAccess` over gRPC with that
   exchanged token as the bearer credential, and asserts `allowed: true`,
   `reason_code: "allowed"`.

The point being proved: **the gateway never had to hold or forward the
user's original token** to make an authorization decision on the user's
behalf — only a narrower, audience- and scope-restricted, actor-annotated
one, exactly as `docs/api/token-exchange.md`'s "one rule everything below
serves" (an exchange may only ever narrow) describes.

## What it requires

- A running, bootstrapped AXIAM instance (see
  [`scripts/e2e-bootstrap.sh`](../../scripts/e2e-bootstrap.sh)) with **both**
  its REST port and its gRPC port reachable. The gRPC server binds to
  `127.0.0.1` inside the container by default
  (`crates/axiam-api-grpc/src/config.rs`'s `default_host`), which Docker
  cannot publish — see
  [`docker-compose.grpc-port.override.yml`](docker-compose.grpc-port.override.yml)
  in this directory for the one-line fix used by CI (`AXIAM__GRPC__HOST=0.0.0.0`
  plus a `50051:50051` port publish). **Do this only for local/CI smoke
  testing** — the loopback default is a deliberate security posture
  (`crates/axiam-api-grpc/src/config.rs`: "Deploy behind mTLS or an internal
  network when binding to `0.0.0.0`"), never something to flip in a real
  deployment without also putting mTLS or a network boundary in front of it.
- Rust (stable, edition 2024) and `cargo`. This is its **own** Cargo
  workspace (the `[workspace]` table in `Cargo.toml` is empty, not a member
  list — see the comment there), so it builds independently of the main
  repo's workspace at `../../Cargo.toml`: `cargo build` / `cargo run` from
  this directory, no changes to the root `Cargo.toml` needed or wanted.

```bash
docker compose -f docker/docker-compose.e2e.yml \
  -f examples/b3-mesh-delegation-grpc/docker-compose.grpc-port.override.yml \
  up -d --wait
./scripts/e2e-bootstrap.sh
AXIAM_URL=http://localhost:8090 AXIAM_GRPC_URL=http://127.0.0.1:50051 \
  E2E_TENANT_ADMIN_PASSWORD='Tenant@Admin123!' \
  cargo run --manifest-path examples/b3-mesh-delegation-grpc/Cargo.toml
```

`E2E_TENANT_ADMIN_PASSWORD` is **required** and has no default. It is the
password `scripts/e2e-bootstrap.sh` seeds the **tenant** administrator with,
shown above for convenience — it is deliberately not a literal in
`src/main.rs`, because example code gets copied and a credential in source is a
real finding wherever it lands. The second account this example provisions gets
a freshly generated password per run for the same reason.

The tenant admin, not bootstrap's super-admin: the super-admin is
organization-level, signs in naming no tenant, and administers every tenant in
the organization. This example works inside one tenant, so it holds that
tenant's own administrator. Both are seeded; see
[`examples/b6-organization-scope`](../b6-organization-scope/README.md).

## History: the registration gap found while building this example

Step 2's second client registration —
`POST /api/v1/oauth2-clients` with
`"grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"]`
— failed with `400 unknown grant_type` while this example was first being
built: `KNOWN_GRANT_TYPES` in
`crates/axiam-api-rest/src/handlers/oauth2_clients.rs` (shared by the
`create` and `update` handlers) did not yet include the token-exchange grant
URN, even though the engine underneath fully honored a client registered
for it (`crates/axiam-oauth2/src/token_exchange.rs`'s
`TOKEN_EXCHANGE_GRANT_TYPE`, and every token-exchange integration test built
its fixture client by calling `oauth2_client_repo.create(...)` directly —
bypassing this REST validator — per
`crates/axiam-api-rest/tests/token_exchange_test.rs:127`). The gap was
REST-registration-only, and it blocked any external caller from registering
a token-exchange-capable client through the public API, not just this
example. **`KNOWN_GRANT_TYPES` has since been fixed** (it now includes both
the device-flow and token-exchange grant URNs) — this example's step 2
registers cleanly against a current checkout, and this section is left here
as the record of why `main.rs` explicitly checks that registration's status
before proceeding rather than assuming success.

## Verification status

Compiles cleanly (`cargo build --locked`, this directory's own workspace)
against the real, published `tonic`/`prost`/`reqwest` crate versions pinned
in `Cargo.lock`; `cargo fmt -- --check` and `cargo clippy --all-targets -- -D
warnings` are both clean too. Its `build.rs` compiles the client stub
straight from `proto/axiam/v1/authorization.proto` — the same file
`crates/axiam-api-grpc` builds its server from (needs a system `protoc` on
`PATH`, same as that crate's own build; see `examples-smoke.yml`).
**It has not been run against a live server** — no docker daemon in the
environment this was authored in (see the repo root `examples/README.md`),
so nobody has yet watched the full flow succeed end to end against a live
AXIAM instance; it is expected to, now that the registration gap above is
fixed, but that expectation has not been observed.
