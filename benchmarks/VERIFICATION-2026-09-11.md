# Benchmark Suite — Verification Report, 2026-09-11

**Verified against:** server `1.0.0-beta12` at `cdedf33` (workspace `Cargo.toml`), and
all **eleven** SDK checkouts at `1.0.0-beta12` / **SDK contract 1.42** (every one
re-synced on 2026-09-11).

**Benchmarks last substantively touched:** `5f2a4c8` (2026-09-04, "terminate gRPC TLS
in the listener"). Everything below is the delta from there — 87 non-merge server
commits, dominated by the OpenID Connect Basic OP waves (W1–W9) and the OIDF
conformance work — read against `benchmarks/` and `benchmarks/sdk/`.

**Verdict: the harness was not broken, and one thing in it was quietly wrong.**
No scenario, adapter, seed step or SDK bench glue drifted against the server or the
SDKs. What had gone stale was the field that says *which* SDK a measurement came
from, and what had opened was a coverage gap on the endpoint that received most of
the release's new work. Both are addressed on this branch; §3 lists what is
deliberately left open.

This report is the 2026-09 successor to [`UPGRADE-PLAN.md`](UPGRADE-PLAN.md)
(2026-07-17), which remains accurate as the record of *that* review and is not
retrofitted here.

---

## 0. Verified as still CORRECT — no action needed

| Area | Finding |
|---|---|
| **Every scenario endpoint** | Every path the scenarios drive is still registered at the same path and method: `/api/v1/auth/{login,refresh}`, `/api/v1/auth/opaque/{login,register}/start`, `/api/v1/authz/check{,/batch}`, `/api/v1/device/{verify,decide}`, `/api/v1/{resources,resources/{id}/children,roles,roles/{id}/{users,permissions},permissions,reactors}`, `/oauth2/{token,introspect,revoke,jwks,userinfo,device_authorization}`, `/uma2/{perm,rreg/resource_set}` (`crates/axiam-api-rest/src/server.rs`) and `/scim/v2/Users{,/{id}}` (`crates/axiam-scim/src/routes.rs`). |
| **Request shapes** | `LoginRequest` still `{tenant_id?, org_id?, tenant_slug?, org_slug?, username_or_email (alias username), password}`; `RefreshRequest` still `{tenant_id, org_id?}`. `handlers/oauth2.rs` grew by ~2 550 lines and every field it added — the nine OIDC authn-request parameters, `dpop_jkt`, `tenant_id`, the three hop markers — is `Option` and `#[serde(default)]`. Nothing the harness sends changed meaning. |
| **`client_secret_post` still works unchanged** | W8 added `client_secret_basic` and made `token_request_context` fallible, but it fails only on a *malformed* `Authorization: Basic` header. The scenarios send credentials in the form body and no `Authorization` header at all, so they take the same branch they always did. |
| **Client registration (seeding)** | `CreateOAuth2ClientRequest` gained `authn_request_params` and `browser_sso`, both `#[serde(default)]`. The W7 sensitive-scope registration gate refuses `address`/`phone` only; `runner/seed.sh` registers `["openid","uma_protection"]`. Seeding is unaffected. |
| **Proto surface** | `proto/` is byte-identical to `5f2a4c8`. Every gRPC scenario's service, method and field names still match. |
| **Rate-limit extraction** | `runner/rl_prod_check.py` regex-extracts the configured defaults from `crates/axiam-api-rest/src/config/rate_limit.rs` and `crates/axiam-api-grpc/src/{config.rs,middleware/rate_limit.rs}`. The first file is unchanged since `5f2a4c8`; every constant the script names (`default_grpc_authz_per_sec`, `IDENTITY_PER_SEC_MULTIPLE`, `ADMIN_PER_SEC_DEFAULT`, `INFRA_PER_SEC`, `WINDOW_SECS`) still exists under that spelling. |
| **CSRF** | `middleware/csrf.rs` gained the `axiam_op_session` cookie helper and nothing that changes exemptions. `/oauth2/*` is still prefix-exempt and a bearer-only request is still exempt, which is every non-GET call the scenarios make. |
| **ID-token claims (contract 1.42 break)** | 1.42 stops minting `tenant_id`, `org_id` and `email` into the ID token. No scenario and no SDK bench reads an ID token: the `tenant_id` occurrences in `scenarios/` are all query/body parameters. Nothing to change. |
| **SDK bench glue vs contract 1.42** | 1.42's three changes (`dpop_jkt` on PAR, two RFC 8414 discovery members, the ID-token break) all sit outside CONTRACT §1's `login` / `refresh` / `check_access` / `batch_check` and the optional gRPC `get_user_info`. No harness calls PAR or discovery. Confirmed empirically for Rust: `cargo check` of `sdk/rust` against the beta12 SDK checkout is clean. |
| **`sdk/HARNESS-SPEC.md`'s transport split** | "gRPC-capable: Rust, TypeScript, Python, Java, C#, PHP, Go; REST-only: Kotlin, Swift, C, C++" still matches `CLAUDE.md`. |
| **AXIAM target image** | `justfile` derives `BENCH_AXIAM_IMAGE` from the workspace version rather than pinning a literal, so it followed `1.0.0-beta12` on its own. |

---

## 1. Wrong, and fixed on this branch

### 1.1 Eight of eleven SDK benches reported a stale SDK version — silently

`sdk_version` is the field that says which SDK produced a record. It is printed on
every `sdk/dry-run.sh` verdict line and folded into the published report, and a
reader takes it at face value.

Eight benches carried it as a literal compiled into the harness:

| bench | reported | actual |
|---|---|---|
| `go`, `java`, `csharp`, `typescript` | `1.0.0-alpha2` | `1.0.0-beta12` |
| `rust` | `1.0.0-alpha7` | `1.0.0-beta12` |
| `swift` | `1.0.0-alpha12` | `1.0.0-beta12` |
| `kotlin` | `1.0.0-alpha13` | `1.0.0-beta12` |
| `python` | `1.0.0a2` | `1.0.0b12` |

`_pending.sh` carried the same map for `pending` records. `php` derived the version
from Composer but fell back to `1.0.0-alpha2`; only `c` (`axiam_version()`) reported
truthfully, and `cpp` reported `1.0.0` because `axiam::kVersion` is the CMake project
version and carries no pre-release qualifier.

A literal cannot go red. An entire SDK matrix would have been published attributing
beta12 measurements to alphas that no longer exist, and nothing in the harness would
have complained.

**Fix.** `sdk/_sdkversion.sh` resolves the version from the sibling checkout each
bench already builds against — the package manifest where one carries a version
(Cargo.toml, package.json, pyproject.toml, pom.xml, gradle.properties, the csproj),
the newest released `## [x.y.z]` CHANGELOG heading for the five SDKs that publish
from a git tag (Go, PHP, Swift, C, C++). Each `run.sh` sources it and exports
`AXIAM_SDK_VERSION`; each bench prefers that over its literal, which now exists only
as a fallback for a published-package run with no checkout beside it. The next
release bump needs no edit in `benchmarks/` at all.

`sdk/test-sdk-version.sh` pins the resolution against synthetic checkouts (one per
manifest shape, plus the CHANGELOG fallback and the absent-checkout case) and
asserts that every bench still reads the env var and every `run.sh` still exports
it. It is wired into CI's **Bench Harness Self-Tests** job.

### 1.2 The TLS profiles never forwarded the client address

`p1`–`p3` front `axiam-server` with nginx; every edge conf set `X-Forwarded-Proto`
and none set `X-Forwarded-For`. The server therefore keyed every request on the
nginx container address.

This became worth fixing with R-4 (`227aeb9`, landed in this same window and never
reflected here), which made a `TRUSTED_HOPS` misconfiguration observable via a WARN
and `axiam_rate_limit_xff_discarded_total`. The observability deliberately does **not**
cover this case: a request carrying *no* `X-Forwarded-For` is not counted, because a
client with no proxy in front of it is not a misconfiguration. So the harness was
running the one variant of the T-212 shape that says nothing about itself.

**Fix.** Each conf now sets `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`,
and the compose leaves `AXIAM__RATE_LIMIT__TRUSTED_HOPS` at `0` — the correct value
for one reverse proxy, and the topology `docs/deployment/README.md` ships.
`docs/security-profiles.md` gains a "Client IP and the rate limiters" section.

**No measured number moves.** k6 drives every VU from one host, so there is one
client address either way and an `rl=prod` pass still fills a single bucket, which is
what `rl_prod_check.py` compares against the configured limit. What changes is which
code path is measured: `XForwardedForKeyExtractor`'s, as in production.

### 1.3 Stale counts, pins and status claims in the docs

The suite grew from seven SDK benches to eleven without the prose following. Fixed
in `README.md`, `sdk/README.md` and `sdk/HARNESS-SPEC.md`: all eleven are wired, the
7/4 full-transport-vs-REST-only split is stated, and the "as of run 3 no SDK bench
has produced a validated `ok` record" claim — contradicted by `sdk/README.md`'s own
H8 table for several releases — is replaced by a pointer to that table.

Version pins refreshed to `1.0.0-beta12` where they described the current
dependency: `java/pom.xml`'s `${axiam.sdk.version}` fallback, `kotlin/build.gradle.kts`,
`rust/Cargo.toml`'s published-crate comment, the commented-out C# `PackageReference`,
and the eight `TODO.md` files. Historical narrative that names an old version *as
history* (java's account of the alpha2/alpha21 ~/.m2 trap) is left alone.

None of these pins were load-bearing — `java/run.sh` reads the sibling pom, Gradle
substitutes the Kotlin coordinate, Go uses a `replace`, C# a `ProjectReference` — which
is exactly why they had all drifted without anything failing.

`README.md` also had Zitadel at `v4.15.2` while `targets/zitadel/docker-compose.yml`
pins `v4.16.2`.

---

## 2. The coverage gap the last developments opened

Waves W1–W7 (2026-09-07…10) put the largest single body of new server work in this
release behind **one endpoint the harness had never measured**: `GET /oauth2/authorize`.
The authn-request parameter gates, the honour lane, the browser login hop and its OP
session cookie, the cosmetic parameters and the sensitive-scope consent gate all
execute there, on the hot path of the flow every OpenID Connect deployment runs.

Every OAuth2 endpoint *around* it was already measured — `/token`, `/introspect`,
`/revoke`, `/jwks`, `/userinfo`, the device pair, token exchange, UMA — and the one
that starts the flow was not.

**`scenarios/oauth2_authorize.js`** closes it: a bearer-authenticated authorization
request, one measured call per iteration, expecting the RFC 6749 §4.1.2 redirect. It
lands in `PENDING_SCENARIOS` under the same rule `scim_provisioning.js` follows —
checked statically against the handlers and the seed, never executed, and un-pending
an unrun scenario would risk turning a skip into a red matrix cell. One supervised
run with `BENCH_ENABLE_PENDING_SCENARIOS=1` closes it.

Three design choices are argued in the file header and summarised here: the code is
not redeemed (same shape as `device_authorization.js`; redemption deserves its own
cell), PKCE is omitted (required for public clients only, and verified at redemption
— which this cell does not perform), and authentication is the bearer token rather
than the W3 browser hop (the hop needs `browser_sso: true`, which the bench client is
not registered with, and its cost is dominated by `/login` and the password hash,
both already measured by `oauth2_password_login.js`).

`/oauth2/authorize` carries **no rate-limit governor** — unlike `/token`, `/revoke`
and `/introspect` — so the cell is not throttled under `rl=prod` and there is no
`rl_prod_check.py` family to add.

---

## 3. Named follow-ups — deliberately NOT done here

These are real gaps, each stated so the next reviewer does not have to rediscover it.

| Gap | Why it is open |
|---|---|
| **`authorization_code` redemption cell** | `POST /oauth2/token` with `grant_type=authorization_code` does work no other cell measures: code lookup and single-use consumption, PKCE verification, ID-token minting. It needs a per-iteration fresh code, so it is a second scenario, not a second half of `oauth2_authorize.js`. |
| **DPoP as a security dimension** | RFC 9449 sender-constrained tokens now verify a JWS on every resource request, plus the §10 code binding and the §11.1 single-use check. That is a per-request cryptographic cost the profile matrix is built to quantify, and no cell exercises it. It is closer to a `p4-dpop` profile than to one scenario. |
| **`optional_self_signed` mTLS (RFC 8705 §2.2)** | `AXIAM__SERVER__TLS__CLIENT_AUTH` gained a fourth variant; `p3-mtls` exercises only `required` (§2.1 `tls_client_auth`). Covering §2.2 means a self-signed client certificate and a registered thumbprint — a new profile plus seed work. |
| **PAR (`/oauth2/par`)** | Mandatory on the FAPI 2.0 lane and unmeasured. `par.rs` changed in this window (`dpop_jkt`, `request_uri` refusal). |
| **`POST /oauth2/userinfo` (W6)** | The response is byte-identical to the GET; only the form parse differs. Low value, listed so the omission is a decision rather than an oversight. |
| **SCIM `phoneNumbers` / `addresses`** | `crates/axiam-scim` gained both; `scim_provisioning.js` sends neither. It is pending its first run anyway — worth extending in the same pass that un-pends it. |
| **Competitor image pins** | Keycloak `26.7.0`, Zitadel `v4.16.2`. Not checked against upstream in this review (no egress); an operator should re-check before publishing a head-to-head. |

---

## 4. What the operator's dry-run can close

Three scenarios sit in `PENDING_SCENARIOS`, and two of them are pending on nothing
but a first execution:

- `scim_provisioning.js` — seeding and auth are fixed; it has never run.
- `oauth2_authorize.js` — new here; checked statically, never run.
- `oauth2_client_credentials_reactor_hook.js` — genuinely blocked (no admin-session
  helper in `lib/auth.js`, and nothing answers the reactor queue). Not closable by a
  run.

```bash
just target=axiam profile=p2-tls13 bench-up
just target=axiam profile=p2-tls13 bench-seed
BENCH_ENABLE_PENDING_SCENARIOS=1 just target=axiam profile=p2-tls13 scenario=oauth2_authorize bench-run
BENCH_ENABLE_PENDING_SCENARIOS=1 just target=axiam profile=p2-tls13 scenario=scim_provisioning bench-run
```

If a cell passes, drop that file from `PENDING_SCENARIOS` and delete its STATUS block
in the same commit.

The SDK dry-run should now print `1.0.0-beta12` (and `1.0.0b12` for Python) on every
verdict line. A line still naming an alpha means `AXIAM_SDK_VERSION` did not reach
the bench — check that the sibling `axiam-<lang>-sdk` checkout is where `run.sh`
expects it:

```bash
just target=axiam profile=p2-tls13 sdk-dry-run
```

---

## 5. The operator's run — outcome (2026-09-11, same day)

§4 was executed. Both closable cells are closed, and one of them was not a
formality.

| Cell | Result |
|---|---|
| `oauth2_authorize` | **PASS** on its first-ever execution — `ok=636, p95=21ms`. Un-pended. |
| `scim_provisioning` | **FAILED** its first-ever execution: 20 of 907 operations. Un-pended only after the server defect it found was fixed; re-run clean at 470/470 with zero SCIM 500s. |

### 5.1 What `scim_provisioning` found

Every one of the 20 failures was the same thing. A concurrent
`PATCH /scim/v2/Users/{id}` lost a SurrealDB optimistic-concurrency race and
reached the client as HTTP 500, carrying the engine's own words — *"Transaction
write conflict. This transaction can be retried"*. Nothing retried it. An IdP
driving Okta/Entra-shaped provisioning reads those as failed syncs and re-sends
the whole record.

The machinery to handle it already existed and was already unit-tested —
`is_write_conflict`, `MAX_WRITE_ATTEMPTS`, `write_conflict_backoff` all shipped
with the August `increment_failed_logins` fix — but the helper their own
documentation linked to, `retry_on_write_conflict`, had never been written. One
method got a hand-rolled loop; every other contended write got nothing.

Fixed in `axiam-db`: the helper now exists, `UserRepository::update` uses it (so
every administrative and SCIM write is covered), `classify_write_error` stops
reporting a contended write as `Migration failed`, and `is_transaction_conflict`
— whose two literals did not match the message SurrealDB v3 actually emits, and
which guards the single-use consume on `device_grant`, `permission_ticket`,
`pushed_auth_request` and `oauth2_auth_code` — was folded into the one marker set.

### 5.2 Why this is the argument for `PENDING_SCENARIOS`

`scim_provisioning`'s header recorded that its payloads had been checked
statically against the real SCIM DTOs and matched. They did. It still hid a live
server defect, because what it exercises is *concurrency*, and no amount of
reading finds that. "Matches on inspection" was never allowed to count as "runs
green" here, and this is why.

### 5.3 The rest of §4

The base matrix is **22 PASS / 0 WARN / 6 SKIP / 0 FAIL** (3m36s), and the SDK
dry-run is **11 PASS / 0 WARN / 0 SKIP / 0 FAIL** (4m43s) with every language
reporting `1.0.0-beta12` (`1.0.0b12` for Python) — so §1.1's `_sdkversion.sh` fix
is confirmed working end to end. Nothing in §3's named follow-ups changed.

One harness note for the next operator: `bench-up`'s port pre-flight checks the
TLS port but not the gRPC one, so with a conformance `serve-axiam.sh` running
(it holds `127.0.0.1:50051`) the stack dies with a raw daemon error and the next
stage reports `auth.mintUserToken: could not obtain a token for setup (status 0)`
— a connection failure wearing a credentials failure's clothes. `BENCH_GRPC_PORT`
is the knob, as `BENCH_TLS_PORT` is for 8443.
