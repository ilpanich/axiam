# Benchmark Suite — Verification Report & Upgrade Plan

**Verified:** 2026-07-17, against server `1.0.0-alpha3` (workspace `Cargo.toml`) and all seven
SDK repos (`ilpanich/axiam-<lang>-sdk`).
**Benchmarks last touched:** commit `94b3a4a` (2026-07-12, SDK extraction).
**Verdict: an upgrade IS needed.** The harness's endpoint/adapter layer is still correct, but
three things are **broken today** against the current server (seeding, gRPC scenario auth,
authz fixtures), the five pending SDK benches are now unblocked and their wiring notes need
corrections, and several pins/docs are stale.

Each item below lists the files to change, the exact change, and an acceptance check, so it
can be implemented directly (one PR per priority band is a sensible split).

---

## 0. What was verified as still CORRECT (no action needed)

| Area | Finding |
|---|---|
| AXIAM adapter endpoints (`scenarios/lib/targets.js`) | `/api/v1/auth/login`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/jwks`, `/oauth2/userinfo` all match current `crates/axiam-api-rest/src/server.rs` route registration. JWKS is correctly `/oauth2/jwks` (not `/.well-known/jwks.json`). |
| Login body | `{tenant_id, username_or_email, password}` matches the server's `LoginRequest` (which also aliases `username`). |
| gRPC proto usage | `axiam.v1.AuthorizationService/CheckAccess` + `BatchCheckAccess`, fields `tenant_id`/`subject_id`/`action`/`resource_id`/`scope`, `results` array — all match `proto/axiam/v1/authorization.proto`. No proto changes landed since the benchmarks were written. |
| Python bench glue (`sdk/python/bench.py`) | Every import, constructor kwarg, and method call matches `axiam-sdk` `1.0.0a2` (`AxiamClient(*, base_url, tenant_slug, …)`, `login`, `refresh`, `check_access`, `batch_check`, `AccessCheck`). No API drift. |
| TypeScript bench glue (`sdk/typescript/bench.mjs`) | `createNodeClient({baseUrl, tenantSlug})` from `axiam-sdk/node`, `login/refresh/checkAccess/batchCheck` all match `axiam-sdk` `1.0.0-alpha2`. No API drift. |
| CONTRACT.md | Vendored copies in all 7 SDK repos are byte-identical to `sdks/CONTRACT.md` (v1.1, §1–§11). §1 vocabulary (`login`, `verify_mfa`, `refresh`, `logout`, `check_access`/`can`, `batch_check`) unchanged since the 2026-06-30 lock — HARNESS-SPEC's four ops remain valid. |
| Server API stability | No REST route, request/response shape, or proto change landed after `94b3a4a`. alpha1→alpha3 were release/docs-only. |

---

## P0 — Broken against the current server (must fix before any run)

### P0.1 `runner/seed.sh` uses the pre-alpha bootstrap flow (hard failure)

Server commit `406cc97` (2026-07-14) rewrote `POST /api/v1/admin/bootstrap`
(`crates/axiam-api-rest/src/handlers/bootstrap.rs`). The current handler:

- **Creates the org + default tenant itself.** `BootstrapRequest` is
  `{organization_name (required), organization_slug?, tenant_name?, tenant_slug?, email, username, password, setup_token?}`.
  It no longer accepts `org_id`/`tenant_id`.
- **Is gated fail-closed** (D-03a): requires EITHER env `AXIAM_BOOTSTRAP_ADMIN_EMAIL` set on the
  server and matching the request email, OR a valid single-use `setup_token`. Otherwise 403.
- **Is one-shot** (`bootstrap_lock:global`): a second call returns 409.
- **Returns** `BootstrapResponse{message, organization_id, organization_slug, tenant_id, tenant_slug, user_id}`.

`seed_axiam()` in `runner/seed.sh` currently: creates org/tenant rows via raw SurrealDB SQL with
self-generated UUIDs, then POSTs `{org_id, tenant_id, email, username, password}`. Result today:
bootstrap 400s (masked by `|| true`), admin login then fails, seeding aborts.

**Required changes** (`runner/seed.sh`, `targets/axiam/docker-compose.yml`):

1. Delete the raw-SurrealDB org/tenant creation block (the `curl $SURREAL/sql` step) — bootstrap
   now provisions both.
2. Set the gate: add `AXIAM_BOOTSTRAP_ADMIN_EMAIL: "admin@bench.dev"` to the `axiam-server`
   service environment in `targets/axiam/docker-compose.yml` (bench-only; do not touch
   `docker/docker-compose.prod.yml`).
3. Call bootstrap with the new body:
   `{"organization_name":"Bench Org","tenant_name":"Bench Tenant","tenant_slug":"default","email":"admin@bench.dev","username":"admin","password":"Bench@Admin123!"}`
   and parse `organization_id` / `tenant_id` / `tenant_slug` from `BootstrapResponse` into
   `ORG_ID` / `TENANT_ID` / `TENANT_SLUG` (prefer `jq` over `sed`; `jq` is already a documented
   prerequisite in `README.md`).
4. Handle re-seeding: on 409 ("bootstrap already completed"), fall through to admin login and
   recover the tenant id from the login response / `GET /api/v1/auth/me` instead of failing.
5. Drop the now-dead `SURREAL_URL` / `surreal-ns` plumbing and remove the `|| true` on the
   bootstrap curl (it must fail loudly on 400/403 now that the gate exists).

**Acceptance:** `just bench-up target=axiam profile=p0-plaintext && just bench-seed target=axiam`
writes a `results/axiam.seed.env` containing a real (server-issued) `BENCH_TENANT_ID`, and
`just bench-run target=axiam profile=p0-plaintext scenario=oauth2_password_login.js` passes with
error rate < 1%. Running `bench-seed` twice in a row succeeds (idempotent).

### P0.2 gRPC authz scenarios send no authentication (every call UNAUTHENTICATED)

The gRPC `AuthorizationService` is registered `with_interceptor(AuthInterceptor)`
(`crates/axiam-api-grpc/src/server.rs:88`), and the handlers derive identity from **validated JWT
claims** (SEC-003, `services/authorization.rs`) — a request without a valid
`authorization: Bearer <access_token>` metadata entry is rejected with `unauthenticated`.

`scenarios/authz_check_grpc.js` and `scenarios/authz_batch_grpc.js` call `client.invoke(...)`
with no metadata at all, so under the current server 100% of iterations fail.

**Required changes** (both scenario files, optionally `scenarios/lib/auth.js`):

1. Add a k6 `setup()` that mints a token (reuse `mintToken()` from `lib/auth.js` — note the SDK
   flow logs in as `BENCH_USERNAME`, so prefer the `login` builder over `clientCredentials` so the
   token's subject is the seeded user whose grants P0.3 creates).
2. Pass it on every invoke:
   `client.invoke('axiam.v1.AuthorizationService/CheckAccess', req, { metadata: { authorization: `Bearer ${data.access_token}` } })`.
3. Access tokens live 15 minutes; the default run (30s+120s+10s) fits, but add a comment (or a
   re-mint on `PermissionDenied/Unauthenticated`) so longer soak runs don't silently decay.
4. Since identity comes from the JWT, set `subject_id` in the request to the seeded user's UUID
   (see P0.3) — the value must be consistent with the token's subject, not the username string.

**Acceptance:** with a seeded target, `just bench-run target=axiam profile=p0-plaintext
scenario=authz_check_grpc.js` completes with `grpc status OK` check-rate ≥ 99%.

### P0.3 Authz fixtures: non-UUID resource ids, no grants, missing seed exports

Three related problems:

- **REST rejects the defaults outright.** `POST /api/v1/authz/check` deserializes
  `resource_id: Uuid` (`handlers/authz_check.rs`). The wired SDK benches
  (`sdk/python/bench.py:29`, `sdk/typescript/bench.mjs:26`) default `BENCH_RESOURCE_ID` to the
  literal `"bench-resource"` → 400 on every check. The gRPC scenarios use the same default and
  additionally default `BENCH_SUBJECT_ID` to `cfg.username` (`"benchuser"`, not a UUID).
- **Batch suffixing breaks UUIDs.** All four batch call-sites synthesize ids as
  `${RESOURCE}-${i}` — even with a valid UUID in `BENCH_RESOURCE_ID` the suffixed values are not
  UUIDs. Repeat the same resource id N times (or seed N resources) instead.
- **Nothing is granted.** `seed.sh` creates no resource, role, or role-assignment, so even valid
  ids measure only the deny fast-path. The scenarios' own comments say a seeded pair with
  `allowed=true` is required for a meaningful number.

**Required changes:**

1. Extend `seed_axiam()` to provision, via the admin token:
   a benchmark resource (`POST /api/v1/resources`), a role with a `read` permission on it
   (`POST /api/v1/roles` + permission wiring), and assign the role to `benchuser`.
   Capture the resource UUID and the bench user's UUID (from the user-creation response).
2. Export them in the seed env: append `BENCH_RESOURCE_ID=<uuid>` and `BENCH_SUBJECT_ID=<user uuid>`
   to `results/axiam.seed.env` (and document both in `sdk/HARNESS-SPEC.md`'s env list, which
   currently omits them).
3. Fix batch id synthesis in `scenarios/authz_batch_grpc.js`, `sdk/python/bench.py`,
   `sdk/typescript/bench.mjs` (and the future wired benches): reuse `BENCH_RESOURCE_ID` for every
   entry in the batch rather than appending `-${i}`.
4. Add an assertion to the wired SDK benches that `allowed === true` on a warm-up check, so a
   misconfigured grant fails fast instead of silently benchmarking denials.

**Acceptance:** `just sdk-bench sdk=python` emits `status: "ok"` with `errors: 0` for
`check_access` and `batch_check` against a freshly seeded target.

---

## P1 — Coverage and wiring upgrades (the actual "upgrade" work)

### P1.1 Add REST authz k6 scenarios (closes the declared NON-COMPARATIVE gap)

The server exposes `POST /api/v1/authz/check` and `POST /api/v1/authz/check/batch`
(`server.rs:703-721`, with a dedicated `authz_check_per_min` rate-limit tier), but the k6 suite
only measures authz over gRPC. `sdk/HARNESS-SPEC.md` and `sdk/collect.py` both explicitly flag
that SDK `check_access`/`batch_check` overhead is "approximate at best **until a REST-based k6
authz scenario exists**". That scenario is now cheap to add and makes the SDK-overhead numbers
honest.

**Required changes:**

1. New `scenarios/authz_check_rest.js` and `scenarios/authz_batch_rest.js`: mint a token in
   `setup()` (login as `benchuser`), then `POST {baseUrl}/api/v1/authz/check` with
   `{"action":"read","resource_id":"<BENCH_RESOURCE_ID>"}` (batch: `{"checks":[...]}`), bearer
   auth, using `doOp()` from `lib/metrics.js`. Body field names are `resource_id`, `checks`,
   `results`, `reason` (note: gRPC's response field is `deny_reason`, REST's is `reason`).
2. Mark them AXIAM-only in `runner/run-benchmark.sh`'s `filter_scenarios()` (same treatment as
   the gRPC pair) — no competitor has an equivalent endpoint.
3. Update `sdk/collect.py` `OP_TO_SCENARIO`: `"check_access": "authz_check_rest"`,
   `"batch_check": "authz_batch_rest"` — deltas become genuinely comparable (same wire path).
4. Update the corresponding prose in `sdk/HARNESS-SPEC.md` ("Comparing SDK overhead"),
   `docs/methodology.md` §3 scenario table, and `README.md`'s layout/status sections.

**Acceptance:** `just bench-run … scenario=authz_check_rest.js` passes; `sdk/collect.py` prints a
non-"—" overhead column for `check_access`/`batch_check` when both records exist.

### P1.2 Wire the five pending SDK benches (now unblocked, with corrections)

All five SDKs are released (Go/Java/C#/PHP `1.0.0-alpha2`, Rust `1.0.0-alpha7`), and the audit
found the generic TODO instructions are **wrong or incomplete for three languages**. Wire each
bench per `sdk/HARNESS-SPEC.md` (mirror `python/bench.py` / `typescript/bench.mjs`), applying
these per-language corrections (also fold them into each `sdk/<lang>/TODO.md` so the docs stop
misleading):

| Lang | Corrections vs current TODO.md |
|---|---|
| **rust** | Pin `axiam-sdk = "=1.0.0-alpha7"` — alpha…alpha6 fail to build under edition 2024 (`gen` keyword bug fixed in alpha7); an open `"1.0.0-alpha"` req can resolve to a broken version. All ops are `async` → bench needs a Tokio runtime. `check_access(action, resource_id: Uuid, scope)` takes a **`Uuid`** — parse `BENCH_RESOURCE_ID`. Construction is `AxiamClient::builder().base_url(..)?.tenant_slug(..).build()?`. |
| **go** | Instructions basically correct (`NewClient(baseURL, tenantSlug, opts...)`, ctx-first sync methods). `CheckAccess` returns `(bool, string, error)`; `resourceID` is a plain string. If the `1.0.0-alpha2` tag isn't on the module proxy, add `replace github.com/ilpanich/axiam-go-sdk => ../../../../axiam-go-sdk` in the bench `go.mod`. |
| **java** | No public constructor — must use `AxiamClient.builder(baseUrl, tenantId).build()`. Methods: `login`, `refresh`, `checkAccess(action, resourceId[, scope])` → `AccessResult`, `batchCheck(List<AccessCheck>)`; sync + `*Async` twins (sync is simplest for the bench). Bench `pom.xml` needs `exec-maven-plugin` with a `mainClass` for `mvn -q exec:java`. If `io.github.ilpanich:axiam-sdk:1.0.0-alpha2` isn't on Central yet, `mvn install` the SDK repo into the local `.m2` first. |
| **csharp** | **Authz is not on the client**: it's `client.Authz.CheckAccessAsync(action, resourceId, …)` / `client.Authz.BatchCheckAsync(...)` (returns `bool` / `IReadOnlyList<bool>`), and `resourceId` is a **`Guid`**. All ops are `*Async`-only (no sync variants): `LoginAsync`, `RefreshAsync`. Construct with `new AxiamClient(new Uri(baseUrl), tenantId)`. If `Axiam.Sdk 1.0.0-alpha2` isn't on NuGet, use a `ProjectReference` to the local repo. |
| **php** | Package name `axiam/axiam-sdk` correct. `new AxiamClient($baseUrl, $tenant)` positional; `checkAccess()` returns **`bool`** and `batchCheck()` returns `list<bool>` (no result objects — note this in the overhead methodology: PHP does less result-materialization work per call). `composer.json` has no `version` field (tag-derived) — if not on Packagist, use a `path` repository entry pointing at the local repo. |

Cross-language notes to encode once in `sdk/HARNESS-SPEC.md`:

- **`refresh` under concurrency is coalesced.** Rust/Go/Java/C# (and Python/TS) guard `refresh()`
  with a single-flight lock — with `SDK_BENCH_CONCURRENCY=16`, N concurrent refreshes collapse
  into ~1 wire call, so concurrent refresh throughput is not a wire measurement. Spec should
  mandate measuring the `refresh` op **serially** (concurrency 1) in every bench, including
  retro-fitting the Python/TS benches if they currently run it concurrently.
- `refresh()` requires a prior successful `login()` on the same client instance in every SDK.
- Flip each wired language's record to `status: "ok"` and report the real `sdk_version`.

**Acceptance:** `just sdk-bench-all` produces seven records, all `status: "ok"`, and
`sdk/collect.py` renders a seven-row measured table.

### P1.3 `_pending.sh` / README status honesty (small, do with P1.2)

- `sdk/_pending.sh` hardcodes `"sdk_version": "unreleased"` — stale: all SDKs have published
  alphas. If any scaffold remains pending after P1.2, report the real released version.
- `README.md` "Status of components" table and `sdk/README.md` still describe 5 pending
  scaffolds — update once wired.

---

## P2 — Staleness & hygiene

### P2.1 Competitor target pins are outdated

| Target | Pinned | Current (2026-07) | Action |
|---|---|---|---|
| Keycloak (`targets/keycloak/docker-compose.yml`) | `quay.io/keycloak/keycloak:26.4` | **26.7.0** | Drop-in bump (same major; env/health contract unchanged). |
| Zitadel (`targets/zitadel/docker-compose.yml`) | `ghcr.io/zitadel/zitadel:v2.65.0` | **v4.15.2** | **Two majors behind — real migration.** v3/v4 changed defaults (new login UI/v2 flows, config keys); re-verify `start-from-init` flags, `ZITADEL_*` env names, and that the OIDC endpoints used by the adapter (`/oauth/v2/token`, `/oauth/v2/introspect`, `/oauth/v2/keys`, `/oidc/v1/userinfo`) are unchanged (they are standard discovery paths, so likely yes — but confirm against a running v4 before publishing numbers). |
| nginx TLS edge | `nginx:1.27-alpine` | fine | Optional bump to current stable. |
| postgres (both targets) | `postgres:16-alpine` | 17 available | Optional; keep both targets on the same version for fairness. |

Benchmarking against a 2-major-old Zitadel would invalidate any published comparison — treat the
Zitadel bump as required before publishing results, even though the harness itself runs.

### P2.2 README references a file that doesn't exist

`README.md` (directory layout) lists `resource/cadvisor-compose.yml` ("optional richer
telemetry"); the file is absent. Either add a minimal cAdvisor compose or delete the reference.

### P2.3 Bench compose DB-name drift

`targets/axiam/docker-compose.yml` defaults `AXIAM__DB__DATABASE: main` while
`docker/docker-compose.prod.yml` (which it claims to mirror) uses `axiam`. Harmless today only
because `seed.sh`'s raw-SQL path (being deleted in P0.1) was the only consumer — align the bench
default to `axiam` when touching the file for P0.1.

### P2.4 p3-mtls profile cannot be exercised by any SDK bench — document it

No SDK (all 7 audited) exposes an mTLS client-certificate option; the only TLS knob is a
custom-CA for server verification. The k6 protocol scenarios handle p3 fine (`tlsAuth` in
`lib/config.js`), but `sdk/HARNESS-SPEC.md` implies SDK benches run under any profile and lists
`BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` as SDK-bench inputs. Add an explicit limitation note:
SDK benches run p0–p2 only until the SDKs grow an mTLS option (worth filing as an SDK feature
request — the p3 profile text explicitly advertises the IoT/mTLS auth path).

### P2.5 SDK repos vendor a stale `openapi.json` (out of benchmarks/, but found here)

All 7 SDK repos vendor `openapi.json` with `info.version: "1.0.0-alpha"`, while upstream
`sdks/openapi.json` is `1.0.0-alpha3`. Content is otherwise byte-identical apart from the
version string (per the alpha3 release notes), so nothing is functionally wrong — but the
CLAUDE.md re-sync rule says downstream copies must be refreshed. Flag for a routine SDK re-sync;
not a benchmarks change.

---

## P3 — Optional backlog (nice-to-have, not required for a valid run)

1. **`token_revocation` scenario** — `POST /oauth2/revoke` exists and is a standard (RFC 7009)
   comparable flow across all three targets.
2. **`oidc_discovery` scenario** — `GET /.well-known/openid-configuration`; trivially comparable,
   and remediation item CQ-B23 (discovery caching) wants a before/after measurement hook.
3. **MFA verify flow** — `POST /api/v1/auth/mfa/verify` is contract op `verify_mfa`, currently
   unmeasured on both server and SDK sides (would need TOTP seeding; non-trivial).
4. **T19.2 tie-in** — roadmap task "Concurrent BatchCheckAccess" says "benchmark against
   sequential implementation to validate improvement"; the P0.2/P1.1 batch scenarios are that
   gate. Add a `BENCH_BATCH_SIZE` sweep note in `docs/methodology.md` when T19.2 lands.
5. **SDK gRPC-path bench ops** — every SDK also ships an `AuthzGrpcClient`; a `check_access_grpc`
   op per SDK (vs the k6 gRPC baseline) would measure SDK gRPC overhead. Keep out of the four
   canonical ops (contract §1 lock); add as optional extra keys only if the aggregator learns to
   ignore unknown ops (it currently iterates whatever is in `ops`).
6. **AMQP async-authz harness** — still correctly out of scope (k6 has no AMQP executor);
   unchanged from the README's deferral.

---

## Suggested implementation order

1. **PR 1 (P0):** `seed.sh` rewrite + bench-compose gate env + gRPC scenario auth + fixture
   UUIDs/exports. After this the existing suite runs green against `1.0.0-alpha3`.
2. **PR 2 (P1.1):** REST authz scenarios + `collect.py`/docs updates.
3. **PR 3 (P1.2/P1.3):** wire rust/go/java/csharp/php benches (one commit per language), refresh
   TODO/README/status text, serial-refresh rule in HARNESS-SPEC.
4. **PR 4 (P2):** Keycloak/Zitadel bumps (validate Zitadel v4 adapter paths against a live
   container), cAdvisor reference, DB-name default, mTLS limitation note.

Verification for every PR: `just bench-up/bench-seed/bench-run` on `p0-plaintext` and `p2-tls13`
for target=axiam, plus `just sdk-bench-all` — all records valid per `docs/methodology.md` §6
gates (error rate < 1%).
