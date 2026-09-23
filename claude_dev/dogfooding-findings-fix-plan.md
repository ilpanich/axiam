# Fix plan — the `axiam-domo-demo` dogfooding findings (DF-001 … DF-027)

**Date:** 2026-09-21
**Validated against:** `axiam` main @ `2fc0193` (release 1.0.0-beta16 + two chores); every SDK repository at the head that vendors contract 1.48 / the beta16 `openapi.json` (all twelve copies byte-identical, verified by hash)
**Source of the findings:** `axiam-domo-demo` @ `420d0b6`, [`docs/dogfooding-findings.md`](https://github.com/ilpanich/axiam-domo-demo/blob/main/docs/dogfooding-findings.md) — 27 entries, DF-001 … DF-027
**Status: PLANNED — nothing in this document is implemented.** It is a brief for later sessions; §11 carries the kick-off prompt.

> **How this plan was produced.** Every entry was re-read against the code on
> `main` rather than taken at its word — most of the findings were filed
> `reported-from-source-reading` against beta16, and a plan that fixes what a
> finding *says* rather than what the code *does* is a plan that ships the
> wrong patch. §1 is the result of that reading. Six entries turned out to be
> wrong or materially incomplete in ways that change the fix (DF-001, DF-003,
> DF-004, DF-013, DF-014, DF-024), and the reading surfaced **two defects the
> findings do not contain** (§1.7, §1.8). Both are worked here and both should
> be appended to the findings file as DF-028 and DF-029 (§10).

---

## 0. The verdict, one row per finding

Severity is *as filed*. "Fix" means code in this repository or in the SDK
repositories; "Docs" means only prose changes; "Decline" is a decision with a
recorded reason, not an omission. Effort is in single-session units. Model is
the cheapest one that can be trusted with the task under the rule in §2.

| Finding | Component | Severity filed | What `main` actually does (§1) | Decision | Task | Effort | Model |
|---|---|---|---|---|---|---|---|
| DF-001 | `axiam-pki` | high | CSR-carried SAN/KU/EKU are **refused with 400**, not dropped; issued leaves carry **no** SAN, KU or EKU | **Fix** — explicit, name-constrained SAN issuance and a per-type KU/EKU profile | S-7 | high | Opus 5 |
| DF-002 | docs | medium | Docs say Device certificates *do not bind*; the code **requires** the bind for every device login | **Docs** | S-5 | low | Sonnet 5 |
| DF-003 | `axiam-db` | low | `has_role` **has** `UNIQUE(in, out)`; a repeat is a 409, never a duplicate | **Decline** (finding is incorrect) — but the index is *stricter* than the finding assumes; see D-3 | — | — | — |
| DF-004 | gRPC | medium | Reactor CRUD already lives on gRPC; users/roles/resources do not | **Decline** (defer; see D-4) | — | — | — |
| DF-005 | gRPC listener | high | `with_no_client_auth()`; no config key exists; the same listener carries the reactor CRUD surface | **Fix** — client-CA verification on the gRPC listener, off by default | S-8 | medium | Opus 5 |
| DF-006 | `/auth/device` | medium | Access token only, by design | **Decline** (see D-6) | — | — | — |
| DF-007 | docs | low | Nothing in `docs/` mentions RabbitMQ auth backends | **Docs** | S-5 | low | Sonnet 5 |
| DF-008 | all 11 SDKs | high | No SDK sends `X-Axiam-Tenant`; the server side is complete and tested; contract §5.2 rule 1 makes the helper a MAY | **Fix** — contract 1.50 + eleven SDKs | C-0, C-1 … C-11 | high (spread) | Opus 5 (contract, Rust reference, review) · Sonnet 5 (ten ports) |
| DF-009 | 10 of 11 SDKs | high | Only C++ has `authenticate_device()`; the C README **claims** it and does not ship it | **Fix** — same wave | C-0 … C-11 | medium | as above |
| DF-010 | all 11 SDKs | low | Excluded by the registry, but the contract's own §27.0 exclusion table omits the row | **Docs** — contract row + status codes; no helper | C-0 | low | Opus 5 (rides C-0) |
| DF-011 | all 11 SDKs | medium | §27.6 names eight manifest namespaces; seven SDKs ship five, four ship three; none has `metadata`, resource-scoped group bindings or `service_accounts` | **Fix** — contract clarification + eleven SDKs | C-0 … C-11 | high (spread) | as above |
| DF-012 | 7 gRPC SDKs | low | `TokenService` stubs are generated in nine repos and wrapped in none; §10.3's MUST is unsatisfiable | **Fix** — wrap both RPCs; §1 vocabulary amended | C-0 … C-11 | low each | as above |
| DF-013 | REST management | high | All management handlers take `AuthenticatedUser`; `AuthenticatedPrincipal`, `RequirePermission::check_subject` and `has_role` for service accounts **already exist** | **Fix** — bounded: the §27 management families switch extractor | S-9 | high | Opus 5 |
| DF-014 | `/auth/device` | medium | `CnfClaim` with `x5t#S256` exists and is minted for OAuth2 mTLS clients; the device path never sets it | **Fix** — stamp and enforce | S-3 | medium | Opus 5 |
| DF-015 | docs | low | Two sentences in `docs/pki/README.md` say RSA generation fails; `generate_keypair` has handled `Rsa4096` since 2026-08-25 | **Docs** | S-5 | low | Sonnet 5 |
| DF-016 | `healthcheck` | medium | Plain-HTTP default, webpki roots only, no anchor option | **Fix** | S-6d | low | Sonnet 5 |
| DF-017 / DF-025 | `axiam-pki` | high | `prepare_leaf_issuance` never reads `ca_cert.tenant_id`; cross-tenant issuance inside one organization is real and untested | **Fix — first** | S-1 | low | Opus 5 |
| DF-018 / DF-022 | secrets | high / medium | The env provider resolves every key to `AXIAM__AUTH__<NAME>`; three docs pages and four source sites name the wrong variable | **Fix** — messages and docs name the resolved variable; a startup warning catches the legacy spelling; no alias | S-6a | low | Sonnet 5 |
| DF-019 | bootstrap | high | Token logged once; only its hash is stored; no re-mint path | **Fix** — a `setup-token --remint` subcommand gated on "no user exists" | S-6c | low | Sonnet 5 |
| DF-020 | docs | info | `AXIAM__AMQP__TLS__CLIENT_CERT_PATH` is documented in one row; the ordering constraint is not | **Docs** | S-5 | low | Sonnet 5 |
| DF-021 | authz | low (proposal) | Inheritance is unconditional; the one filter is `applicable_role_ids` | **Fix** — an `inherit` flag on the role assignment (the user's proposal, kept; §5 for the alternatives) | S-10 | medium | Opus 5 |
| DF-023 | `axiam-pki` | low | `CN=` is prefixed unconditionally on root, intermediate and generated-leaf paths; docs and the UI placeholder both tell callers to send `CN=` | **Fix** — one subject helper, three call sites | S-6b | low | Sonnet 5 |
| DF-024 | rate limit | medium | `login_per_min` = 10 by design (G7 decision); the 429 already names itself — **and the device mTLS login has no limiter at all** | **Decline** the default change; **Fix** the unlimited device login (§1.7) | S-2 | low | Sonnet 5 |
| DF-026 | console image | medium | Three literal `proxy_pass` targets rendered by envsubst; no `resolver` | **Fix** | S-11 | low | Sonnet 5 |
| DF-027 | `/auth/device` | low | 403 via a string match on the error message | **Fix** — 401, and the string match goes | S-4 | low | Sonnet 5 |

Also worked, from the reading rather than the findings: **§1.7** the device
login rate limiter (S-2) and **§1.8** the C SDK README claim (C-10).

Counts: **17 fix**, **4 docs-only** (bundled into one task), **4 declined**
with a decision each, 2 new defects.

---

## 1. What reading `main` established that the findings did not have

Each item below changes a fix. They are numbered so later sections can cite
them.

### 1.1 DF-001 — the CSR extensions are refused, not dropped

`inspect_csr` (`crates/axiam-pki/src/ca.rs:1129-1143`) collects `subjectAltName`,
`keyUsage` and `extendedKeyUsage` from the CSR and `sign_csr`
(`crates/axiam-pki/src/cert.rs:508-519`) turns a non-empty list into
`AxiamError::Validation` — a 400 with the extension named. The rationale is
recorded at `cert.rs:471-483`: Vault's `sign-verbatim` would honour them, so a
silent strip would make the two custodians disagree. The finding's
reproduction ("the extension is absent regardless of what the CSR asked for")
describes a CSR that was refused, not a leaf that was issued.

What is true and matters: `leaf_params` (`cert.rs:712-726`) sets only
`CN`, `IsCa::NoCa` and the validity window. **Issued leaves carry no SAN, no
KU and no EKU**, on both leaf paths, and both request structs
(`SignCertificateCsrRequest` at `handlers/certificates.rs:90-100`,
`CreateCertificateRequest` at `:25-34`) have no field to ask for any. The
code calls the per-type profile "a follow-up to be decided once, for both,
with a migration note" (`cert.rs:698-711`). S-7 is that follow-up.

### 1.2 DF-003 — the index exists, and is stricter than the finding assumes

`idx_has_role_unique ON TABLE has_role FIELDS in, out UNIQUE`
(`crates/axiam-db/src/schema.rs:1313`, SCHEMA_V19). A repeated assignment is a
unique-index violation, classified to `DbError::AlreadyExists` and rendered
as **409** (`repository/role.rs:311-315`). Two tests pin it:
`a_subject_holds_a_role_at_most_once`
(`crates/axiam-api-rest/tests/role_assignment_scope_test.rs:582`) and
`assign_to_user_duplicate_edge_is_rejected`
(`crates/axiam-db/tests/role_repository_gaps_test.rs:413`).

The consequence the finding did not see: the key is `(subject, role)` with
**no resource component**, so a subject holds a given role *once* — globally
or under one resource, never under two. A resident who owns two apartments
cannot hold `resident` at both; a concierge assigned to two sites cannot
hold `concierge` at both. The demo's seed data happens not to need it (one
concierge per site, residents in one apartment), but a hierarchical model
will. That is a maintainer decision, recorded as **D-3**, not a fix in this
plan: widening the key to `(in, out, resource_id)` inverts a pinned test and
a documented invariant, and SurrealDB 3.x cannot express the partial index
that would keep "one global assignment" unique alongside it
(`schema.rs:2886-2889`, test at `:4114`).

### 1.3 DF-004 — gRPC already carries a management surface, for one object

`axiam.v1.ReactorAdminService` (`proto/axiam/v1/reactor.proto:23`) exposes
`CreateReactor`, `UpdateReactor`, `DeleteReactor`, `GetReactor`,
`ListReactors`, `ListReactorEvents` — mirrored field-for-field on the REST
DTOs, registered at `crates/axiam-api-grpc/src/server.rs:418`. So the
accurate statement is "no user / role / resource / certificate management on
gRPC", and the precedent for adding one exists. It is still declined here
(**D-4**): the surface is large, the demo has a working REST path, and the
listener it would ride on has no client-certificate verification until S-8
lands — which is the order these two should be taken in, if ever.

### 1.4 DF-013 — the plumbing is complete; only the extractor is narrow

Three extractors exist in `crates/axiam-api-rest/src/extractors/auth.rs`:
`AuthenticatedUser` (`:313`, `axiam:user` only), `AuthenticatedServiceAccount`
(`:1146`, `axiam:m2m` only, **used by no handler today**) and
`AuthenticatedPrincipal` (`:1214`, either). `RequirePermission::check_subject`
(`crates/axiam-api-rest/src/authz.rs:207`) applies RBAC "identically to both
kinds of principal — there is deliberately no `is_machine` parameter".
The `has_role` edge already relates `service_account` records
(`repository/role.rs:261-319`), and the assignment routes already exist
(`handlers/roles.rs:620`, `:703`, `:721`). Exactly two routes accept
`axiam:m2m`: `POST /authz/check` and `/authz/check/batch`. S-9 widens that
set; it does not build anything new.

### 1.5 DF-014 — `cnf` is built, minted elsewhere, and never handed to devices

`AccessTokenClaims.cnf: Option<CnfClaim>` (`crates/axiam-auth/src/token.rs:189`)
with `x5t#S256` (RFC 8705) and `jkt` (RFC 9449), constructors at
`:323-341`, enforcement table at `:1756-1810`. OAuth2 mTLS client credentials
mint it (`crates/axiam-oauth2/src/token.rs:1242-1258`, thumbprint at
`crates/axiam-oauth2/src/mtls.rs:227`). `issue_service_account_token`
(`axiam-auth/src/token.rs:1240-1253`) has no `cnf` parameter and
`AccessTokenSpec::service_account` never calls `.cnf(...)`. S-3 is the
plumbing between two things that exist.

### 1.6 DF-024 — the default is a decision, and the response already names itself

`login_per_min` defaults to 10 (`config/rate_limit.rs:544`) and
[`rate-limit-posture-decision.md`](rate-limit-posture-decision.md) (G7) rules
that **no human-endpoint default moves** and that no preset may raise one.
The 429 carries `Retry-After` and `{"error":"rate_limit_exceeded", …}` from
both limiter layers (`extractors/rate_limit.rs:134-152`,
`middleware/rate_limit_shared.rs:107-116`). A client that reads that as an
authentication failure is mapping the status wrong on its side — worth
checking in `domo-bootstrap`'s error handling, and outside this plan.

### 1.7 New — the device mTLS login is not rate-limited at all

`crates/axiam-api-rest/src/server.rs:261`:

```rust
.route("/device", web::post().to(handlers::auth::device_auth::<C>))
```

A bare route: no `build_governor`, no `RateLimitShared`, unlike every
neighbouring auth resource (`/auth/login` at `:181-182`, OPAQUE, WebAuthn and
federation sign-in at `:196-514`). It is in `PUBLIC_PATHS`
(`permissions.rs:309`) and CSRF-exempt (`middleware/csrf.rs:87`). A TLS
handshake with a client certificate is the most expensive thing an
unauthenticated caller can make the server do, and the one auth endpoint that
performs it is the one with no limiter. **S-2.** Suggested findings entry:
DF-028.

### 1.8 New — the C SDK README advertises an operation that does not exist

`axiam-c-sdk/README.md:193` documents `POST /api/v1/auth/device`; no symbol
in `include/` or `src/` performs it. Only the C++ SDK has
`authenticate_device()` (`src/client.cpp:903`). **C-10** ships the
operation; until then the README is wrong. Suggested findings entry: DF-029.

### 1.9 DF-002 — the documentation error is the dangerous direction

`docs/pki/README.md:548-559` and `website/src/docs/operate.ts:685` state that
Device-type certificates "are not bound to anything" and that "looking for a
bind endpoint for a device is looking for something that does not exist".
`DeviceAuthService::authenticate_der` (`crates/axiam-pki/src/mtls.rs:153-160`)
refuses every certificate with no bound service account, Device type
included; the happy-path test binds before it authenticates
(`tests/device_auth_test.rs:412`). The docs also omit three handler
requirements (`certificates:bind`, Active status, not expired). An integrator
who follows the docs gets a fleet that cannot log in.

### 1.10 DF-005 — what sits on the unverified listener

`build_grpc_rustls_server_config` (`crates/axiam-server/src/tls.rs:1355-1364`)
calls `with_no_client_auth()`, and its own doc comment (`:1270-1277`) records
that as a deployment decision deferred from T-234. Since then the reactor
CRUD surface (§1.3) was added to that listener, and gRPC skips session
revocation by default (`axiam-api-grpc/src/config.rs:105-106`). The finding's
severity is right for the wrong reason: it is not only `CheckAccess` that is
token-only.

---

## 2. Model assignment — the rule and the price

Two models are eligible: **Claude Opus 5** (`claude-opus-5`, $5 / $25 per
million input / output tokens) and **Claude Sonnet 5** (`claude-sonnet-5`,
$2 / $10). The rule is the one
[`mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md) §2 and
[`sdk-oidc-sso-plan.md`](sdk-oidc-sso-plan.md) §4 already apply:

- **Opus 5** when the task touches token minting, client authentication or
  certificate issuance, changes what an authorization decision returns, or has
  to reconcile a normative text with existing behaviour across crates or
  repositories. A wrong call is a security finding, and the price difference
  is smaller than one remediation round.
- **Sonnet 5, effort `high`,** when the task is a bounded port of a pattern
  that already exists in the repository — a config key, a status-code change, a
  documentation page, a subcommand shaped like `healthcheck`, a port of a
  reference implementation into another language. The task section is the
  whole brief.

By that rule: **Opus 5** for S-1, S-3, S-7, S-8, S-9, S-10, C-0, C-1 and C-12;
**Sonnet 5** for S-2, S-4, S-5, S-6a–d, S-11 and the ten SDK ports C-2 … C-11.
Where a task mixes both kinds it is split into lettered parts so the cheaper
model does the bounded part (S-6 is four such parts).

Rough cost, so the choice is visible: the Opus tasks are the ones where a
session reads several crates before writing (S-7, S-9, C-0); everything
Sonnet-assigned is one crate or one repository with a worked example next to
it.

---

## 3. Order, and how many pull requests

Split **by generated-artifact exposure and by risk**, not by severity, so
that each PR can be reverted alone and the SDK wave re-vendors
`sdks/openapi.json` once.

| PR | Tasks | Branch | Why together |
|---|---|---|---|
| **A** — security, server | S-1, S-2, S-3, S-4 | `fix/dogfooding-security` | The four `axiam-pki` / `/auth/device` changes; A ships first, alone, and is the one to backport if anything is |
| **B** — correctness and operator experience, server | S-6a, S-6b, S-6c, S-6d, S-5 | `fix/dogfooding-operator` | Small, independent, no authorization semantics; one commit each |
| **C** — console image | S-11 | `fix/console-resolver` | Touches `docker/` only; its own CI path filter |
| **D** — authorization model | S-10 | `feat/assignment-inherit` | Schema migration + engine + REST + OpenAPI; must not share a PR with anything that could mask a precedence regression |
| **E** — gRPC client-certificate verification | S-8 | `feat/grpc-client-auth` | Listener change; off by default; own rollback |
| **F** — service accounts on management routes | S-9 | `feat/m2m-management` | ~100 handler signatures; a PR nobody wants merged with anything else |
| **G** — name-constrained SAN issuance and KU/EKU profile | S-7 | `feat/pki-leaf-profile` | Largest server item; changes every issued leaf; migration note required |
| **H** — contract 1.50 | C-0 | `docs/contract-1.50` | After A–G merge, so the contract describes shipped behaviour and the spec it re-vendors is final |
| **I₁ … I₁₁** — SDK fan-out | C-1 … C-11 | one per SDK repo, `feat/contract-1.50` | Rules in §8 |
| **J** — conformance review | C-12 | `docs/contract-1.51` | One row per divergence, §28.11's form |

Order: **A → B, C in parallel → D → E → F → G → H → I (Rust first, ten in
parallel) → J.** D before E and F because both later PRs add tests that
assert authorization outcomes, and those tests should be written against the
engine that has `inherit`. G last among the server PRs because it is the one
most likely to need a second round.

Every `axiam` commit: `cargo fmt --all --check`, `cargo clippy` with
`-D warnings` on the CI toolchain (or the per-crate forms
`CLAUDE.md`'s disk-hygiene section prescribes, with `cargo clean` between
tasks), `scripts/check-crate-layering.py`, `scripts/check-doc-links.sh`,
`scripts/check-config-key-coverage.py`, a `CHANGELOG.md` entry under
`[Unreleased]`, and the threat-model bookkeeping of §9 **in the same commit**.

---

## 4. Server tasks

Each task names its files, its tests, its invariant and its records. The
fixed row set in **Cost, counted** is the one
[`issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) uses, so the two
plans can be read side by side.

### S-1 — `prepare_leaf_issuance` binds a tenant signing CA to the acting tenant (DF-017, DF-025) — Opus 5

> **EXECUTED — 2026-09-22, PR A, commit 1 of 4.**
>
> **Shipped.** `IssuingScope` (`crates/axiam-pki/src/cert.rs`, re-exported from
> the crate root) carries what the caller *is*; `prepare_leaf_issuance` takes it
> and the acting tenant, and matches the CA against both **immediately after the
> lookup**, ahead of the status and validity-window checks. `generate` and
> `sign_csr` gained the parameter and pass `input.tenant_id` as the acting
> tenant. One site covers the Vault custodian too, as the plan predicted: the
> check precedes `store_for`.
>
> **Tests.** Five in `sign_csr_test.rs` — `a_tenant_signing_ca_of_another_tenant_is_not_found`,
> `a_tenant_may_sign_under_its_own_signing_ca`,
> `an_organization_ca_is_not_usable_by_a_tenant_principal`,
> `a_foreign_ca_is_not_found_even_when_it_is_revoked` (the ordering probe, not in
> the plan — see below), and the I4 twin
> `an_organization_level_principal_may_still_issue_under_the_org_ca`. Four
> `generate` twins in `cert_test.rs`. Two at the wire in `certificate_test.rs`:
> `sign_csr_cannot_reach_another_tenants_signing_ca` beside the
> cross-organization one, and its I4 twin
> `sign_csr_under_the_organization_ca_still_works_for_an_organization_principal`.
> `sign_csr_test`: 25 passed.
>
> **What the plan did not anticipate.**
>
> 1. **`user.organization_level` is the wrong flag, and using it would have
>    broken the I1.** The plan says "pass `user.organization_level` alongside
>    `user.tenant_id`". That flag is set only by `resolve_active_tenant`, i.e.
>    only when a request names *another* tenant through `X-Axiam-Tenant` — which
>    `handlers/org_scope.rs:59-63` already says in as many words. An organization
>    administrator acting on its own organization sends no such header, so the
>    flag is `false` for exactly the call the I1 protects, and reading it would
>    have made the organization CA unreachable by everyone. Resolved instead
>    through a new `org_scope::is_organization_principal`, the residence half of
>    `require_organization_principal`, which reads the caller's own tenant record.
> 2. **The existing test suites all issued leaves under the organization CA as a
>    tenant principal** — that was the shape the defect allowed, so it was the
>    shape the fixtures used. 26 call sites across six `axiam-pki` test files now
>    pass `IssuingScope::Organization` explicitly (they are, accurately, the
>    organization-principal case), and the seven leaf tests in
>    `axiam-api-rest/tests/certificate_test.rs` were moved onto a real tenant
>    signing CA through a new `tenant_signing_ca!` macro — the two-tier shape the
>    product deploys. `a_leaf_outliving_its_issuer_is_refused_with_the_real_maximum`
>    now quotes 363 days rather than 364, because its issuer is the intermediate.
> 3. **A disclosure-ordering test the plan did not name.** Placing the check
>    after the status check would let an outsider distinguish "no such CA" from
>    "revoked CA" by the message. `a_foreign_ca_is_not_found_even_when_it_is_revoked`
>    pins the order.
> 4. **The OpenAPI 404 text.** The plan says no OpenAPI change. Two
>    `#[utoipa::path]` response descriptions are nonetheless wrong after the fix
>    ("No such issuing CA in this organization"), and `generate` documented no
>    404 at all although it could always return one. Both are corrected and
>    `sdks/openapi.json` is regenerated in this commit — a description that
>    contradicts the handler is worse than a regeneration the plan did not
>    schedule.
> 5. **The threat model file is behind its own documents.**
>    `threat-model-stride.md` carries T-272 … T-280 (the Phase 21 wave of
>    2026-09-17); `Axiam.json` and `threat-modeling-and-security.md` both still
>    stood at 271. The next number free in *all three* is therefore **281**, which
>    is what the new threat uses; `threatTop` is 281 while the file holds 272
>    entries. Writing the nine missing entries into the Threat Dragon file from
>    the text `threat-model-stride.md` already holds is a maintainer task, noted
>    in `threat-modeling-and-security.md`'s wave entry and **not** done here.
> 6. **T-98 claimed this was already enforced.** Its mitigation said issuance for
>    a tenant "is anchored at that tenant's path-length-zero intermediate". It was
>    not; the entry is corrected in place rather than extended, and points at
>    T-281.
>
> **Records.** T-281 (Axiam.json, both STRIDE documents, counts updated);
> `gen-threat-model.mjs` run — *"threatModel.ts: 9 diagrams, 272 threats (259
> mitigated, 13 open)"* — generated files reverted. Roadmap Phase 22 / T22.1.
> CHANGELOG under **Security**. `docs/pki/README.md` gains "Which CA a caller may
> issue under", with the reach table and the upgrade paragraph.


**The defect.** `prepare_leaf_issuance` (`crates/axiam-pki/src/cert.rs:124-212`)
fetches the issuing CA scoped to the organization (`ca_repo.get_by_id(org_id,
issuer_ca_id)`, `:146`; the query is `WHERE organization_id = $org_id`,
`repository/ca_certificate.rs:300-311`), checks status and window, and
**never reads `ca_cert.tenant_id`** — the field
`crates/axiam-core/src/models/certificate.rs:49-57` defines precisely to say
which tenant a signing CA signs for. Both REST handlers (`generate` at
`handlers/certificates.rs:48-82`, `sign_csr` at `:139-173`) check only
`certificates:generate` and pass `user.tenant_id` through. A tenant
administrator therefore mints a leaf under another tenant's CA, and the row
records `tenant_id` = theirs, `issuer_ca_id` = the other tenant's. The demo
confirmed it at runtime and then rode it to a full MQTT session (DF-025).

**The fix.** Thread the acting tenant into `prepare_leaf_issuance` (from
`input.tenant_id` in `generate`, `cert.rs:235`, and `sign_csr`, `:527`) and
add, immediately after the lookup at `:146`:

- if `ca_cert.tenant_id` is `Some(t)` and `t != acting_tenant` → refuse;
- if `ca_cert.tenant_id` is `None` (an organization-scoped CA) → also refuse
  for a tenant-scoped principal, **unless** the caller is organization-level
  (`organization_level == true` on the authenticated context). Issuing
  directly under the organization root is exactly the thing the tenant-CA
  tier exists to prevent, and the finding names it.

Refuse as **`NotFound`**, matching the cross-organization precedent
(`a_ca_in_another_organization_is_not_found`, `tests/sign_csr_test.rs:547`):
a CA the caller may not use is a CA the caller cannot see. Apply the same
check to the Vault custodian path (`cert.rs:408-419` region) — the check sits
before custodian resolution, so one site covers both.

**Subject namespace (the narrower closure the finding also names).** Not in
S-1. It would require the CSR CN to name a service account of the acting
tenant, and today nothing in the code or the contract makes `CN=<service
account UUID>` a rule — the demo adopted it as a convention. S-1 closes the
hole at the CA; the convention is recorded in §4.S-7 as a possible future
profile rule, not imposed here.

**Cost, counted.**

| Item | Needed? | Where |
|---|---|---|
| Signature change | yes | `prepare_leaf_issuance(org_id, tenant_id, organization_level, issuer_ca_id, …)`; both callers |
| Handler change | yes | pass `user.organization_level` alongside `user.tenant_id` |
| Schema / migration | no | |
| OpenAPI + registry | no | no DTO changes; the 404 is already a documented response |
| Tests | yes | `crates/axiam-pki/tests/sign_csr_test.rs`: `a_tenant_signing_ca_of_another_tenant_is_not_found`, `an_organization_ca_is_not_usable_by_a_tenant_principal`, and the I4 twin `an_organization_level_principal_may_still_issue_under_the_org_ca`; `crates/axiam-pki/tests/cert_test.rs`: the same three for `generate`; `crates/axiam-api-rest/tests/certificate_test.rs`: `sign_csr_cannot_reach_another_tenants_signing_ca` end to end, next to `sign_csr_cannot_reach_another_organizations_ca` (`:679`). The section header at `sign_csr_test.rs:543` says "tenant and issuer scope" and tests org scope only — the new tests make the header true |
| Docs | yes | `docs/pki/README.md` tenant-CA section: one sentence stating the rule |
| CHANGELOG | yes | **Security** |
| Records | yes | new threat entry (cross-tenant leaf issuance inside an organization), Mitigated on landing; §9 |

**I1.** A tenant principal issuing under its own tenant's CA, and an
organization-level principal issuing under the organization CA, behave
byte-for-byte as today. Existing rows with mismatched `tenant_id` /
`issuer_ca_id` (the demo minted some) are **not** migrated: revocation is the
operator's act, and `just smoke-teardown` already does it downstream. The
docs say so.

### S-2 — the device mTLS login gets a rate limiter (§1.7; suggested DF-028) — Sonnet 5

> **EXECUTED — 2026-09-22, PR A, commit 2 of 4.**
>
> **Shipped exactly as specified.** `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`,
> default 60, per IP, in the machine family, both layers on `/auth/device`
> (`build_governor` + `RateLimitShared("device_login")`) as on `/auth/login`.
> Preset values 300 (`gateway`) and 3 000 (`mesh`) — the same 5x and 50x
> `token_per_min` takes, so the family scales by one rule rather than by taste;
> the plan left the numbers to the executor.
>
> **Tests.** `crates/axiam-api-rest/tests/device_login_rate_limit_test.rs`,
> six tests driving the real `register_api_v1_routes` wiring so a regression
> to a bare route fails rather than passing quietly:
> `device_login_is_rate_limited_per_ip` (with its `Retry-After`),
> `one_exhausted_address_does_not_refuse_another`,
> `login_per_min_is_unchanged_by_the_device_knob` (the I4 twin, asserting both
> the unmoved `10` and that the buckets do not cross),
> `the_shipped_default_is_sixty_per_minute` (the I1, as arithmetic over the
> token lifetime rather than as a bare constant),
> `device_login_limit_scales_with_the_machine_preset`, and
> `an_explicit_device_login_value_beats_the_preset`.
>
> **What the plan did not anticipate.**
>
> 1. **`documented_presets_match_applied_profiles` needed extending, and one
>    sibling test needed leaving alone.** The plan names the first. There are
>    two tables in `config/rate_limit.rs` keyed on `ENV_*` constants: the
>    posture-doc pair (`documented_defaults_match_shipped_config` and
>    `documented_presets_match_applied_profiles`), which the new row joins, and
>    `public_benchmark_doc_shipped_defaults_match_code`, which asserts every
>    knob it lists appears in `benchmarks/PUBLIC_BENCH_ANALYSIS.md`. Adding the
>    device row to the second would have failed: that document is a record of a
>    measurement run, and this limit is sized from the honest traffic rather
>    than from capacity, so there is nothing measured to put in it.
> 2. **Two prose sentences enumerate the machine family** — one in
>    `docs/deployment/README.md`'s `PROFILE` row, one in
>    `rate-limit-sizing.md` §3 — and both had to gain "device login" or the
>    table above them would contradict them.
> 3. **`check-config-key-coverage.py` wants the key on the website too.** The
>    plan names `docs/deployment/README.md` and the rate-limit page; the gate
>    reads `website/src/docs/configuration.ts` and fails a key documented only
>    in `docs/`. Four documentation sites in total, then: the posture table,
>    the deployment config reference, the website configuration page, and the
>    two family sentences.
>
> **Records.** Threat T-282 on the `mTLS device auth` cell (Denial of service,
> Medium, Mitigated); both STRIDE documents, counts updated;
> `gen-threat-model.mjs` run — *"threatModel.ts: 9 diagrams, 273 threats (260
> mitigated, 13 open)"* — generated files reverted. Roadmap T22.2. CHANGELOG
> under **Security**. Docs: the posture table, the deployment config reference
> row, and the two family sentences. No OpenAPI change: the endpoint's contract
> is unchanged and a 429 is not a documented response on any route.


**The fix.** A new knob in the **machine family** —
`AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, default **60**, per IP — wrapped on
`/auth/device` exactly as `/auth/login` is at `server.rs:181-182`:
`build_governor(device_login_per_min)` plus
`RateLimitShared::new("device_login", device_login_per_min)`. It belongs in
the machine family so the `gateway` / `mesh` presets scale it with `token`
and `introspect` (G7's structure; `config/rate_limit.rs:123` says human
endpoints are never touched by a preset — this one is not a human endpoint).
Keying stays per-IP (`AXIAM__RATE_LIMIT__KEY`), and a fleet behind one NAT
is the deployment's reason to choose a preset, which the docs say.

**Cost, counted.**

| Item | Needed? | Where |
|---|---|---|
| Config key | yes | `config/rate_limit.rs`: field, `ENV_DEVICE_LOGIN_PER_MIN`, default, validation ≥ 1, preset row |
| Docs | yes | `docs/deployment/README.md` config reference + the rate-limit page; `scripts/check-config-key-coverage.py` will fail until it is |
| Tests | yes | `crates/axiam-api-rest/tests/` rate-limit suite: `device_login_is_rate_limited_per_ip` (61st call in a minute is 429 with `Retry-After`), `device_login_limit_scales_with_the_machine_preset`, and the I4 twin `login_per_min_is_unchanged_by_the_device_knob` (asserting the `10`); `documented_presets_match_applied_profiles` (`:1325`) must be extended, not weakened |
| CHANGELOG | yes | **Security** |
| Records | yes | threat entry: unauthenticated mTLS handshake amplification, Mitigated; §9 |

**I1.** With the knob at its default, a device logging in on the default
900 s lifetime never sees a 429 (one handshake per 15 min against 60 per
min). No existing limiter default moves.

### S-3 — device tokens carry `cnf` / `x5t#S256` and are enforced against the presenting certificate (DF-014) — Opus 5

> **EXECUTED — 2026-09-22, PR A, commit 4 of 5.**
>
> **Half the task did not need doing, and finding that out was the task.** The
> plan says "**Read how OAuth2 mTLS-bound tokens are enforced on REST today
> before writing a line** — if that enforcement lives in the same extractor,
> this is one more call site; if it lives only in introspection output, the REST
> enforcement is new." It lives in the same extractor, and more generally than
> that: `enforce_sender_constraint` sits inside `validate_presented_token`,
> which is the tail of `parse_validated_claims`, which **every** extractor
> reaches — `AuthenticatedUser`, `AuthenticatedServiceAccount`,
> `AuthenticatedPrincipal` and the audit middleware's cache alike. The gRPC
> interceptor has its own copy reading `peer_certs()`. Both are keyed on
> `claims.cnf.is_none()`, so they began enforcing the moment the claim
> appeared. **No enforcement code was written, and none needed to be.**
>
> **Shipped.** `issue_service_account_token` gains `cnf: Option<CnfClaim>` and
> passes it through `AccessTokenSpec::cnf`, which already existed.
> `CertificateAuthenticated` gains `certificate_thumbprint: Option<String>`,
> set in the extractor and only on the `VerifiedClientCert` branch.
> `device_auth` turns it into `CnfClaim::from_certificate_thumbprint`.
> `issue_service_account_client_credentials_token_enriched` gains the parameter
> for symmetry as the plan asks, passing `None` at its one caller.
>
> **What the plan did not anticipate.**
>
> 1. **No `thumbprint_s256` move.** The plan expected layering to force it into
>    `axiam-auth`. It does not: the computation happens in `axiam-api-rest`
>    (layer 6), which already depends on `axiam-oauth2` (layer 4) and already
>    calls `axiam_oauth2::mtls::thumbprint_s256` from `enforce_sender_constraint`
>    eleven lines away. `check-crate-layering.py` is content. Moving it would
>    have been churn with a third copy of a one-line function as the reward —
>    the gRPC interceptor already keeps its own, and says why.
> 2. **The trusted-proxy path must NOT be bound.** The plan does not mention it.
>    `enforce_sender_constraint` reads `VerifiedClientCert` off the connection
>    and refuses the `X-Client-Certificate` header by construction, so a token
>    bound on the header path would be one AXIAM refuses on its own next
>    request. The thumbprint is therefore recorded only on the native mTLS
>    branch, and the asymmetry is documented at the field, in `docs/pki/README.md`
>    and in T-283 rather than left to be discovered.
> 3. **There is no "stolen device token" residual to flip.** The plan says the
>    existing one "becomes Mitigated"; no such entry exists in either STRIDE
>    document. Entered as a new threat, **T-283**, Mitigated on arrival.
> 4. **The positive native-mTLS direction is not reachable from the test
>    harness**, so the plan's `a_device_token_presented_with_a_different_certificate_is_refused`
>    cannot be written at the HTTP layer. `actix_web::test::TestRequest` builds
>    every request with `conn_data: None` and `HttpRequest::new` is
>    `pub(crate)`, so no test can put a verified certificate on a connection —
>    the limitation `oauth2_userinfo_post_test.rs` already records in those
>    words for the same reason. The three properties are pinned in `axiam-auth`
>    instead, against `verify_token_binding` itself: refused with no
>    certificate, refused with a different one, accepted with the right one,
>    plus the I1. What is not covered is the three-line extractor branch that
>    sets `Some`, and this block is where that is said rather than implied.
> 5. **Two suites broke on S-1 and S-2 and are repaired in their own commit**
>    (`6d42a51`), ahead of this one: `device_auth_test.rs` issued device
>    certificates with a tenant token against the organization CA (S-1's 404)
>    and sent requests to a now-rate-limited route with no peer address (S-2's
>    `500 no peer address`). My runs for those two tasks covered the suites the
>    plan named and the suites I edited; this is neither, and the miss is
>    recorded in that commit's message rather than folded away.
>
> **Records.** T-283 on the `mTLS device auth` cell (Spoofing, High, Mitigated);
> both STRIDE documents, counts updated; `gen-threat-model.mjs` run —
> *"threatModel.ts: 9 diagrams, 274 threats (261 mitigated, 13 open)"* —
> generated files reverted. Roadmap T22.3. CHANGELOG under **Security**.
> `docs/pki/README.md` gains "The token a device gets back is bound to its
> certificate", with the proxy asymmetry, the gRPC consequence and the upgrade
> note. Contract §6.1 is C-0's, in PR H, as the plan schedules. No OpenAPI
> change: the token is opaque to the spec.


**The fix, in two halves, in this order.**

1. **Stamp.** `issue_service_account_token` (`axiam-auth/src/token.rs:1240`)
   gains `cnf: Option<CnfClaim>`; `AccessTokenSpec::service_account`
   (`:640-654`) passes it through. `device_auth`
   (`handlers/auth.rs:867-897`) computes
   `CnfClaim::from_certificate_thumbprint(thumbprint_s256(der))` from the
   verified peer certificate the `CertificateAuthenticated` extractor already
   holds (`extractors/cert_auth.rs`) — reuse `axiam_oauth2::mtls::thumbprint_s256`
   or move it to `axiam-auth` if layering forbids the import
   (`scripts/check-crate-layering.py` decides; `axiam-oauth2` is above
   `axiam-auth`, so the move is the likely answer). The sibling
   `issue_service_account_client_credentials_token_enriched` (`:1303`) gains
   the same parameter for symmetry, unused until S-9.
2. **Enforce.** Wherever an `axiam:m2m` token is accepted over REST
   (`extract_service_account`, `AuthenticatedPrincipal` — today only
   `/authz/check` and `/authz/check/batch`; after S-9, the management
   families) and over gRPC (`crates/axiam-api-grpc/src/middleware/auth.rs`,
   which already reads `x5t` for OAuth2-bound tokens): **a token that carries
   `cnf.x5t#S256` MUST be presented on a connection whose verified client
   certificate has that thumbprint**, per RFC 8705 §3 and contract §10.1
   rule 9. Build the `SenderConstraintEvidence::mtls(...)` from the
   connection's `VerifiedClientCert` extension and let the existing table at
   `token.rs:1756-1810` decide. **Read how OAuth2 mTLS-bound tokens are
   enforced on REST today before writing a line** — if that enforcement lives
   in the same extractor, this is one more call site; if it lives only in
   introspection output, the REST enforcement is new and the task records
   that it is.

**What this deliberately does not do.** It does not make `cnf` optional per
tenant. A device that obtained its token by presenting a certificate is
always able to present it again; the one caller this breaks is a device that
logs in over mTLS and then talks to AXIAM over a connection with no client
certificate — which is the theft scenario the claim exists to close. The
Twin's local verification is the SDK's business: contract §10.1 rule 9 binds
`JwksVerifier`, and **C-1 verifies the Rust SDK honours it with evidence**
before the demo relies on it.

**Cost, counted.**

| Item | Needed? | Where |
|---|---|---|
| Layering | maybe | `thumbprint_s256` may move to `axiam-auth`; the layering script is the referee |
| gRPC | yes | interceptor evidence for m2m tokens (it exists for OAuth2 tokens; confirm the path is shared) |
| OpenAPI | no | the token is opaque to the spec |
| Tests | yes | `crates/axiam-api-rest/tests/device_auth_test.rs`: `a_device_token_carries_the_certificate_thumbprint` (decode, compare with the presented DER), `a_device_token_presented_without_its_certificate_is_refused` (401, on `/authz/check` over a plain connection), `a_device_token_presented_with_a_different_certificate_is_refused`; I4 twin `a_device_token_presented_with_its_certificate_is_accepted` on the same route; gRPC twin in `crates/axiam-api-grpc/tests/` |
| Docs | yes | `docs/pki/README.md` device-auth section and `docs/api/` token page: the claim, and what a relying party checks |
| Contract | yes, in C-0 | §6.1: device tokens are certificate-bound; §10.1 rule 9 already covers the client side |
| CHANGELOG | yes | **Security** |
| Records | yes | the existing "stolen device token" residual becomes Mitigated; §9 |

**I1.** A token minted before this change (no `cnf`) is accepted exactly as
today until it expires — the check is "if `cnf` is present"; that is the
migration, and it lasts one access-token lifetime.

### S-4 — an unbound certificate is a 401 (DF-027) — Sonnet 5

> **EXECUTED — 2026-09-22, PR A, commit 5 of 5.**
>
> **Shipped exactly as specified.** The `AuthorizationDenied` arm and its string
> match are gone; every `AxiamError::Certificate` on this path is now
> `AuthenticationFailed` → 401, like its three siblings. The `#[utoipa::path]`
> responses lose the 403 row, and `sdks/openapi.json` plus
> `sdks/management-registry.json` are regenerated.
>
> **What the plan did not anticipate.**
>
> 1. **The test the plan says to "flip" asserted nothing to flip.**
>    `device_auth_unbound_cert_returns_error` asserted `!= 200`, which passed
>    for 401 and 403 alike — which is why the status could be wrong for as long
>    as it was. It is renamed `device_auth_unbound_cert_returns_401` and now
>    asserts the status *and* that the body still names the case.
> 2. **The I4 twin needed inventing.** A change that collapses one status into
>    another can pass its own test by collapsing the distinction too, so
>    `the_other_device_auth_refusals_are_still_401_and_still_distinct` walks an
>    unbound certificate and a certificate AXIAM never issued through the same
>    route and asserts both the shared 401 and the two different bodies. That is
>    the assertion the plan's "nothing is newly disclosed" argument rests on,
>    and it was worth writing down rather than asserting in prose.
> 3. **The 200 description gained a sentence** about the `cnf` claim S-3 added,
>    since the spec is regenerated here anyway and the response had changed
>    shape one commit earlier without the description saying so.
>
> **Records.** No threat entry: this changes which status a refusal carries, not
> whether it refuses, and no entry claimed the old one. CHANGELOG under
> **Changed**, with the client-side migration stated. Roadmap T22.4.


**The fix.** Delete the special-case arm at
`crates/axiam-api-rest/src/extractors/cert_auth.rs:245-250` that turns
`"not bound to a service account"` into `AuthorizationDenied`. Every
`AxiamError::Certificate` on the device-auth path then maps to
`AuthenticationFailed` → **401**, like its siblings (self-asserted
certificate, untrusted header, unknown certificate). Update the OpenAPI
response line at `handlers/auth.rs:865` (403 → 401, same description) and
regenerate. The string match was also the coupling the second agent flagged:
a reworded message in `axiam-pki` silently changed the status.

**Reasoning, so it is not re-litigated.** A certificate bound to no principal
identifies nobody; 403 asserts an identity that was not established. The
finding's counter-argument — 403 might hide "unknown" vs "known but unbound"
from an anonymous caller — does not hold: both are 401 after this change and
the bodies are already distinct messages, so nothing is newly disclosed.

**Cost, counted.** Tests: flip `device_auth_unbound_cert_returns_error`
(`tests/device_auth_test.rs:512`) to assert 401 and add its twin
`device_auth_unknown_cert_returns_401` if absent. OpenAPI + registry
regenerated (`--dump-openapi`, `check-spec-digest.py`,
`gen-management-registry.py --check`). Docs: the endpoint's row. CHANGELOG:
**Changed**. Records: none.

### S-5 — the documentation bundle (DF-002, DF-007, DF-015, DF-020) — Sonnet 5

> **EXECUTED — 2026-09-22, PR B, commit 5 of 5.**
>
> **Shipped.** All four prose fixes, each re-validated against the code first.
>
> - **DF-002.** `authenticate_device` resolves `get_bound_service_account` and
>   returns "certificate is not bound to a service account" when it answers
>   `None` (`crates/axiam-pki/src/mtls.rs:154-160` — the plan says 153-160; PR
>   A's T22.4 moved it by a line). So the bind is required for **every**
>   certificate that authenticates, `Device` included, and the "looking for
>   something that does not exist" paragraph was wrong in the expensive
>   direction. `docs/pki/README.md` now gives the four-step order, the
>   `certificates:bind` permission, the same-tenant requirement for both
>   records, and the `Active` / not-expired checks the bind handler makes
>   (`handlers/certificates.rs:360-395`). The website's IoT walkthrough gains
>   the bind as its own step, its warning is inverted, and the service-account
>   page carries a note saying the same.
> - **DF-015.** `generate_keypair` routes `Rsa4096` to the `rsa` crate and hands
>   rcgen a PKCS#8 key (`crypto.rs:70-102`); `cert_generate_rsa4096_ca_succeeds`
>   says in its own doc comment that this arm used to be pinned as a failure and
>   no longer is. Both sentences are replaced by the real trade-off: RSA-4096
>   keygen is a probabilistic prime search, seconds on a server and tens of
>   seconds with a wide variance on small ARM hardware, inside `spawn_blocking`
>   behind the crypto semaphore — so the request path is not stalled but a
>   client timeout sized for Ed25519 will fire.
> - **DF-007 + DF-020.** A new `###` between "There is no way to skip
>   verification" and the configuration reference. The `scope` claim half was
>   verified rather than repeated: `issue_service_account_token`'s own
>   documentation states that the device path has no way to request scopes and
>   that a service account registers none, and `AccessTokenSpec::scopes` omits
>   the claim for an empty slice — so a device token carries no `scope` at all
>   and `rabbitmq_auth_backend_oauth2` has nothing to read.
>
> **What the plan did not anticipate.**
>
> 1. **One commit, not four.** S-5 says "one commit each". PR B's task list in
>    §3 counts S-5 as one task, and §9 binds the records — CHANGELOG, roadmap
>    entry, this block — to the *task's* commit. Splitting four prose changes
>    across four commits would have meant either four partial record sets or
>    three commits that violate §9, and nothing in the diff becomes easier to
>    review for it.
> 2. **`authentication.ts` needed an addition, not a correction.** The plan
>    lists `website/src/docs/authentication.ts:1199,1219` alongside the
>    `operate.ts` sites. Neither line is wrong: 1199 is the bind endpoint's row
>    in the service-account API table and 1219 is the mTLS introduction. What
>    was missing is that the bind applies to devices too, so the row's summary
>    says so and a note beneath the table states it.
> 3. **The line numbers had all drifted**, partly because of this PR's own
>    earlier commits: `docs/pki/README.md:535-559` is now 592-617, `:89-91` is
>    100-102, `:358-359` is 369-370, and the deployment guide's line 921 is
>    1156. Each was located by content.
>
> **Also in this commit, deliberately outside the plan** (agreed with the
> requester before starting; the third deferred item, an unexplained
> intermittent `500` from CA-certificate creation during e2e fixture setup, is
> a real unknown in CA generation and gets its own change):
>
> - `users_rate_limit_split_test.rs:99,230` built **response** cookies with
>   `Cookie::build(...).finish()` for what is a request cookie — the same latent
>   CodeQL `rust/insecure-cookie` alert PR A fixed in its own file, fixed the
>   same way and for the same stated reason.
> - `frontend/e2e/matrix/tenancy.spec.ts` snapshotted tenant B's users table
>   with no wait while the tenant-A half waits 20 s. An empty table makes the
>   "tenant A's users are gone" assertion vacuous and the "tenant B's admin is
>   listed" one fail — an intermittent failure that reads as a tenancy bug and
>   is not one. It now waits for the first tenant-B row, as its twin does.

Four prose fixes, one commit each, no code:

1. **DF-002** — `docs/pki/README.md:535-559` and
   `website/src/docs/operate.ts:679,685` (+ `authentication.ts:1199,1219`):
   Device-type certificates **require** the bind; state the order (service
   account → certificate → bind → login), the permission
   (`certificates:bind`), the Active and not-expired requirements, and that
   the certificate must exist in the caller's tenant. Drop the "looking for
   something that does not exist" paragraph. Cite `mtls.rs:153-160` in the
   commit message so the next reader can check.
2. **DF-015** — `docs/pki/README.md:89-91` and `:358-359`: RSA-4096
   generation is supported under both custodians (`crypto.rs:70-102`,
   pinned by four tests). Remove the two sentences; replace with the actual
   trade-off (RSA keygen time on small hardware) so the decision the demo
   made is one a reader can make too.
3. **DF-007 + DF-020** — `docs/deployment/README.md`, new `###` under
   "Securing the broker (AMQP over TLS)" (line 921), between "There is no way
   to skip verification" and the configuration reference: (a) with broker-wide
   `fail_if_no_peer_cert`, AXIAM's own AMQPS client needs a certificate
   before AXIAM exists to issue one — issue it offline from the same root and
   say so; (b) AXIAM tokens are not consumable by
   `rabbitmq_auth_backend_oauth2` (the `scope` claim is application-defined
   and empty on the device path); an integrator putting AXIAM in front of
   RabbitMQ uses certificate login plus an HTTP auth backend, as the demo
   does. Two paragraphs, no new config keys.

Gates: `scripts/check-doc-links.sh`, the website lint job. CHANGELOG:
**Documentation**. Records: none.

### S-6 — operator-experience fixes (DF-018/022, DF-023, DF-019, DF-016) — Sonnet 5

Four independent parts; one commit each on PR B.

#### S-6a — messages and docs name the variable the env provider reads (DF-018, DF-022)

> **EXECUTED — 2026-09-22, PR B, commit 1 of 5.**
>
> **Shipped.** One resolver, `axiam_core::secrets::env_var_name`, is now the
> single answer to "which variable is this secret read from";
> `EnvSecretProvider::var_name` delegates to it. Every message, doc comment,
> guide, website block, compose file and `just` recipe that named one of the
> dead spellings now names the resolved one. A new
> `axiam_server::legacy_env::legacy_secret_env_warnings` produces one `WARN`
> per legacy spelling that is set while the variable AXIAM reads is not; it is
> wired in `main.rs` immediately after `read_secret` is bound.
>
> **Tests.** `axiam-auth`: `var_name_is_what_the_docs_say` pins the four names.
> `axiam-core`: `the_overridden_three_keep_their_shipped_spellings` and
> `every_other_key_is_auth_prefixed` (the latter over `ALL_KEYS` + `ALL_SECRETS`,
> so a new secret cannot quietly acquire a third convention).
> `axiam-server::legacy_env`: five —
> `a_legacy_spelling_alone_is_reported_with_the_variable_that_is_read`,
> `all_four_are_reported`, `the_amqp_signing_key_is_not_treated_as_legacy`,
> and the two I4 twins `a_correct_deployment_is_silent` and
> `both_spellings_set_is_silent`. `scripts/check-config-key-coverage.py`
> passes, self-test included.
>
> **What the plan did not anticipate.**
>
> 1. **`AXIAM__AMQP__SIGNING_KEY` is not a legacy spelling, and warning on it
>    would have been a false alarm.** The plan lists it as the fourth variable
>    to check for. It is a real, honoured variable: `load_config` runs
>    `config::Environment::with_prefix("AXIAM").separator("__")` and
>    `AmqpConfig` has a `signing_key` field, so it deserialises — which
>    `main.rs:359-366` says in as many words, including that the provider's
>    `AXIAM__AUTH__AMQP_SIGNING_KEY` merely takes precedence when both are set.
>    Telling an operator whose deployment works that it does not is worse than
>    saying nothing. Excluded, with `the_amqp_signing_key_is_not_treated_as_legacy`
>    pinning the exclusion and the reason written where the list is.
> 2. **A fourth spelling the plan did not name is dead too:**
>    `AXIAM__FEDERATION_ENCRYPTION_KEY` (`config.auth.federation_encryption_key`
>    comes from `read_key(FEDERATION_ENCRYPTION_KEY)` only). It took the
>    vacated slot in the warning table.
> 3. **The defect is not confined to prose. The repository's own recipes set
>    the dead names.** `justfile:287,289` (`just dev-up` / `just prod-up`),
>    `benchmarks/justfile:119-120`, `benchmarks/targets/axiam/docker-compose.yml:76-77`
>    and `conformance/scripts/serve-axiam.sh:77-78` all exported spellings
>    nothing reads — so the shipped development stack, the benchmark stack and
>    the conformance harness have been running with the email key, the GDPR
>    pepper, the PKI key and the federation key *unset*, which is why the mail
>    consumer's "NOT spawned" error is a familiar line. Fixed with the docs;
>    this is the half of DF-018 that had a running consequence.
> 4. **The resolver belongs in `axiam-core`, not `axiam-auth`.** The plan says
>    to render through `EnvSecretProvider::var_name`. Six of the message sites
>    are in `axiam-pki` (`pgp.rs`, `ca_key_store.rs`), which sits below
>    `axiam-auth` and cannot depend on it. The mapping moved to
>    `axiam_core::secrets::env_var_name` — beside `env_var_override`, the table
>    it consults — and the provider now delegates. No layering edge added.
> 5. **Messages keep literal names rather than a function call.** The plan asks
>    for `var_name(key)` at each site. Most sites are doc comments and
>    `#[error]` attributes, where a call is impossible or unreadable; and
>    `check-config-key-coverage.py` is built to scan *literals*, so rendering
>    them at runtime would make the documentation gate blind to exactly these
>    keys. The pin is `var_name_is_what_the_docs_say` instead: it fails if the
>    resolver and the printed name ever disagree.
> 6. **The coverage gate needed exemptions, not acceptance.** The plan says it
>    "must accept the resolved names" — it already would have. What it refuses
>    is the *legacy* names, which survive as literals in
>    `axiam_server::legacy_env` so the warning can name them. Four `EXEMPT`
>    entries, each stating that the key is read by nothing and which documented
>    key replaces it.
> 7. **Left alone, deliberately.** `claude_dev/` and `.planning/` are records of
>    what was decided when, not instructions to a deployment. And
>    `threat-model-stride.md:1960`, `ThreatDragonModels/Axiam/Axiam.json` and
>    the generated `website/src/threatModel.ts` quote the legacy spelling inside
>    a threat *description*: S-6a's records are "none", and editing the model
>    would desync the committed generated file, so this goes with the
>    threat-model reconciliation PR A already flagged as a maintainer task.
> 8. **Citations re-validated against `main` @ `4b482f0`.** The `main.rs` sites
>    the plan names (172, 631, 1111, 1124, 1194, 2087) are all still the right
>    lines; `crates/axiam-core/src/secrets.rs:166-174` is now 153-174 after an
>    earlier doc-comment growth, and the claim it supports is correct.

**Decision (D-1): one name per secret, no alias.** The env provider resolves
every logical key to `AXIAM__AUTH__<NAME>` (`crates/axiam-auth/src/secrets.rs:85`)
except the three overrides in `crates/axiam-core/src/secrets.rs:166-174`.
Accepting the unprefixed spelling too would give three secrets two names
each, which is the trap the finding describes from the other side.

**The fix.**

1. Every message that names a secret's environment variable renders it
   through `EnvSecretProvider::var_name(key)` instead of a literal — the
   sites are `crates/axiam-server/src/main.rs:172,631,1111,1124,1194,2087`,
   `crates/axiam-api-rest/src/webhook.rs:61,126`,
   `crates/axiam-api-rest/src/handlers/email_config.rs:46`.
2. Docs: `docs/deployment/README.md:215-218`, `docs/pki/README.md:42,178`,
   `docs/admin/email-delivery.md:46`, `docs/compliance/gdpr-compliance.md:127`
   name the resolved variables. Add one sentence to the secrets section
   stating the rule: *under the env provider every logical key is
   `AXIAM__AUTH__<KEY>`; the three exceptions are …*.
3. **A startup warning for the legacy spelling.** At the point
   `main.rs:289-293` builds `read_key`, check the environment for each of
   `AXIAM__PKI__ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`,
   `AXIAM__GDPR_PSEUDONYM_PEPPER` and `AXIAM__AMQP__SIGNING_KEY`; if one is
   set and its resolved name is not, `warn!` naming both. Never read the
   value from the legacy name.

**Tests.** `crates/axiam-auth/src/secrets.rs` unit: `var_name_is_what_the_docs_say`
pinning the four names the docs now print. `crates/axiam-server`: a test
over the warning helper with a fake environment map (not `set_var`), and its
I4 twin (nothing set → no warning). `scripts/check-config-key-coverage.py`
must accept the resolved names.
CHANGELOG: **Fixed**. Records: none.

#### S-6b — `subject` is a common name, and a `CN=` prefix is understood, once (DF-023)

> **EXECUTED — 2026-09-22, PR B, commit 2 of 5.**
>
> **Shipped.** `axiam_pki::subject::subject_common_name` — its own module, not
> a private function in `cert.rs`, because three call sites in two files use it
> and one of them is a CA path. Called **once per operation, at the top**, in
> `CaService::generate`, `CaService::generate_intermediate` and
> `CertService::generate`: the normalised value then reaches the certificate,
> the `subject` column and (under `vault_pki`) the derived intermediate name,
> so the three cannot disagree. Docs, OpenAPI descriptions, the admin-UI
> placeholder, the end-to-end fixtures and the two mTLS check scripts all show
> the bare form.
>
> **Tests.** Six unit tests in `subject.rs` (`a_bare_subject_is_unchanged`,
> `a_single_cn_component_is_understood_once`, `normalisation_is_idempotent`,
> `a_multi_rdn_subject_is_refused`, `an_empty_subject_is_refused`,
> `the_refusal_says_what_is_accepted`); the plan's trio plus its I4 twin in
> `ca_test.rs` (and a fourth, over the derived intermediate subject),
> `intermediate_ca_test.rs` and `cert_test.rs`; plus
> `a_refused_subject_issues_nothing`, which pins that the refusal precedes
> issuance rather than following it. `ca_test`: 9, `intermediate_ca_test`: 13,
> `cert_test`: 22, all passing.
>
> **What the plan did not anticipate.**
>
> 1. **Two of the three cited line numbers point somewhere else now.**
>    `ca.rs:1338` is inside `mod import_tests` — a test helper — not the
>    intermediate path; the real one is `intermediate_params` at `ca.rs:951`.
>    `cert.rs:719` is now `leaf_params` at `cert.rs:793`, and there is a
>    *second* `DnType::CommonName` push at `cert.rs:441`, on the
>    remote-custodian branch that builds a CSR rather than a certificate.
>    Normalising at the three `DnType::CommonName` sites as the plan says would
>    therefore have fixed the certificate and left the stored `subject` column
>    wrong on every path, which is half the finding. Normalising at the entry
>    point fixes both halves and covers the CSR branch for free.
> 2. **`intermediate_subject` needed it too.** Under `vault_pki` custody the
>    intermediate's name defaults to `format!("{} Intermediate Authority",
>    input.subject)`, so an un-normalised root subject put `CN=` in the *middle*
>    of a generated name. Both fields are normalised.
> 3. **The end-to-end matrix fixture breaks without a change the plan does not
>    mention.** `frontend/e2e/helpers/matrix-fixture.ts` creates its six CAs and
>    certificates with `CN=`-prefixed subjects and is idempotent by looking each
>    one up **by its stored subject**. Once the server normalises, that lookup
>    can never match what it created, so every re-run would try to create them
>    again. The fixture now uses bare names, with a comment saying why.
>    `scripts/e2e-mtls-check.sh` and `scripts/e2e-mtls-native-check.sh` were
>    moved with it for consistency (they do not look up by subject, so they were
>    not broken — only wrong).
> 4. **The existing tests needed no edits, as the plan predicted**, and that
>    held: `cert_test.rs:373`, `crud_test.rs:149`, `mtls_chain_test.rs:110` and
>    the rest pass `"CN=…"` and now get the DN they always meant. Nothing in
>    `crates/` asserted a stored subject *with* the prefix, which was checked
>    rather than assumed.
> 5. **An empty subject is now a `Validation` error.** The plan's rule implies
>    it ("trim; empty → `Validation`") but no existing path rejected an empty
>    subject, so this is new behaviour on a case that previously produced a
>    certificate with an empty common name. It is strictly better and is
>    pinned by `an_empty_subject_is_refused`.
> 6. **Refused subjects are refused before issuance.** Because normalisation is
>    the first statement of each method, a bad subject costs no keygen, no
>    custodian round trip and leaves no row — pinned by
>    `a_refused_subject_issues_nothing` rather than left to the reader.

**Decision (D-2): accept a bare CN or exactly one `CN=<value>` RDN; refuse
anything else containing `=`.** A full DN parser (RFC 4514) for a field that
becomes a single CN is scope the certificate does not use.

**The fix.** One helper in `axiam-pki` — `subject_common_name(&str) ->
Result<String, AxiamError>`: trim; empty → `Validation`; no `=` → the string;
matches `^CN=(.+)$` case-insensitively with no `,` or `+` in the value → the
value; otherwise → `Validation("subject must be a bare common name or a
single CN= component")`. Call it at the three `DnType::CommonName` sites:
`ca.rs:146` (root), `ca.rs:1338` (intermediate), `cert.rs:719` (generated
leaf). Store the **normalised** value in the `subject` column so the row and
the certificate agree (today they differ by one `CN=`, `crud_test.rs:149`).
Fix the doc comments (`handlers/ca_certificates.rs:648`,
`models/certificate.rs:64,312`), `docs/pki/README.md:440`, and the UI
placeholder `frontend/src/pages/certificates/CertificatesPage.tsx:305`
(to `device-001`). `frontend/src/lib/download.ts:37,46` keeps its strip; it
is harmless either way.

**Tests.** `crates/axiam-pki/tests/intermediate_ca_test.rs`:
`a_cn_prefixed_subject_yields_a_single_cn` (parse the cert, assert the DN),
`a_multi_rdn_subject_is_refused`; the same pair in `ca_test.rs` and
`cert_test.rs`; I4 twin `a_bare_subject_is_unchanged`. Existing tests that
pass `"CN=…"` (`cert_test.rs:373`, `crud_test.rs:149`,
`mtls_chain_test.rs:110`) are **left as they are** and now produce the DN
they always meant. CHANGELOG: **Fixed**. OpenAPI: doc-comment change only
→ regenerate. Records: none.

#### S-6c — `axiam-server setup-token --remint` (DF-019)

> **EXECUTED — 2026-09-22, PR B, commit 3 of 5.**
>
> **Shipped.** `axiam_db::remint_bootstrap_setup_token` returns a three-way
> `SetupTokenRemint` — `Minted(token)`, `RefusedUserExists`,
> `RefusedTokenConsumed` — rather than a `Result`, because two of the three are
> not failures: they are the security argument. Both gates run **before** the
> delete, so a refused call leaves the existing token working. "Delete then
> mint" is one private `mint_setup_token` shared with
> `mint_bootstrap_setup_token_if_needed`, as the plan asked, so the two paths
> cannot drift into producing differently-shaped tokens. `main.rs` prints the
> token with `println!` and everything else to stderr; exit 0 / 2 / 1.
>
> **Tests.** Three in `seeder_default_data_test.rs`:
> `remint_replaces_the_previous_hash` (one row before, one row after, a
> different hash — replaced, not added), and the two refusals, each asserting
> the stored hash is **unchanged** afterwards. Five over the argv table in
> `axiam_server::cli`, including the I4 twin
> `an_unrecognised_argument_still_serves`.
>
> **What the plan did not anticipate.**
>
> 1. **There is no setup-token threat entry to amend.** The plan's records line
>    says "the setup-token threat entry gains the subcommand and its gate;
>    status unchanged". No such entry exists: `bootstrap_setup_token`,
>    `admin/bootstrap` and `SECHRD-04` appear nowhere in `Axiam.json`,
>    `threat-model-stride.md` or `threat-modeling-and-security.md`; the
>    "setup token" hits in the STRIDE document are all the **MFA** setup token,
>    a different credential. Since the subcommand adds a second credential path
>    to the endpoint that creates the first super-admin, this is a new entry
>    rather than no entry: **T-284**, on `AXIAM deployment (N replicas, HPA)` in
>    the deployment diagram — the element a `kubectl exec` reaches — Elevation
>    of privilege, High, Mitigated on arrival. `threatTop` 283 → 284;
>    `gen-threat-model.mjs` parses it (275 threats in the JSON, still nine short
>    of the documents, which is PR A's flagged reconciliation and not this
>    wave's) and the generated files are reverted.
> 2. **The argv parse moved into the library.** The plan asks for "a unit test
>    next to the `healthcheck` one". There is nothing to put it next to:
>    `tests/healthcheck.rs` re-implements the probe rather than calling it,
>    because `main.rs` cannot be linked from an integration test. Rather than
>    add a second untestable branch, the whole parse became
>    `axiam_server::cli::parse`, a pure function over the arguments, and
>    `main.rs` matches on its result. One branch justifies it on its own:
>    `setup-token` with the flag missing or mistyped must **not** fall through
>    to `Serve` and start a second server against the production datastore.
> 3. **Migrations run first.** The plan says "loads the configuration, connects
>    to the datastore". A datastore that has never served has no
>    `bootstrap_setup_token` table to write to, and `run_migrations` is
>    idempotent and is what boot does anyway. One line, before the re-mint.
> 4. **The two gates are not one gate.** The plan lists them together; they are
>    separate checks because a datastore can carry a consumed token and no
>    `user` row — a restore, a purge, a rolled-back bootstrap — so neither
>    implies the other. `remint_refuses_once_a_token_was_consumed` constructs
>    exactly that state.
> 5. **The documentation went to `docs/admin/README.md`, with a pointer from
>    `docs/deployment/README.md`.** The plan names the deployment guide, which
>    says nothing about bootstrap at all; the Gate 1 / Gate 2 description an
>    operator would be reading when they discover the loss is in the
>    administration guide. The full "I lost the setup token" section is there,
>    under a heading the deployment guide links to by anchor.

**The fix.** A third subcommand next to `healthcheck` and `--dump-openapi`
(`main.rs:185-210`): `setup-token --remint`. It loads the configuration,
connects to the datastore, and:

- if any `user` row exists **or** any `bootstrap_setup_token_consumed` row
  exists → prints a one-line refusal and exits **2**; this is the whole
  security argument — the token is only ever re-mintable on a deployment
  that has no administrator yet, which is the state the finding is stuck in;
- otherwise deletes every `bootstrap_setup_token` row, mints a fresh one
  through the existing `mint_bootstrap_setup_token_if_needed` path
  (`crates/axiam-db/src/seeder.rs:153-196`, refactored so the "delete then
  mint" is one function), and prints the token to **stdout only** — not
  through `tracing`, so it does not land in the container log a second
  time.

The docs get a "I lost the setup token" paragraph in
`docs/deployment/README.md` (the operator's path was "wipe the volume").
No `--print`: the plaintext is not stored, and storing it would be the wrong
fix.

**Tests.** `crates/axiam-db` seeder unit: `remint_replaces_the_previous_hash`,
`remint_refuses_once_a_user_exists`, `remint_refuses_once_a_token_was_consumed`
(the I4 twins). The subcommand's argv parsing gets a unit test next to the
`healthcheck` one. CHANGELOG: **Added**. Records: the setup-token threat
entry gains the subcommand and its gate; status unchanged.

#### S-6d — `healthcheck` can probe a TLS listener (DF-016)

> **EXECUTED — 2026-09-22, PR B, commit 4 of 5.**
>
> **Shipped.** `axiam_server::healthcheck` — `resolve(var)` over an environment
> reader and `run(&Probe)`, both called from `main.rs`. The scheme follows the
> listener, the port follows `AXIAM__SERVER__PORT`, and
> `AXIAM_HEALTHCHECK_CA_FILE` names trust anchors; with none set, an `https`
> self-probe trusts the server's own `AXIAM__SERVER__TLS__CERT_PATH` chain. No
> insecure switch, and an empty or unreadable anchor bundle is a failure rather
> than a silent fall-back to the platform trust store.
>
> **The plan's open question, answered empirically.** *Does webpki accept an
> end-entity certificate as a trust anchor?* **Yes, when that certificate is its
> own issuer** — `a_self_signed_server_certificate_is_a_usable_trust_anchor`
> stands a real rustls listener up and probes it. So the zero-configuration
> default is sound for the self-signed certificate an internal direct-TLS
> deployment usually carries. The neighbouring case is *not*, and the
> documentation says so: a **CA-issued leaf with its issuer absent** from the
> chain file anchors nothing, which is
> `a_ca_issued_leaf_without_its_issuer_is_not_a_usable_anchor` and is exactly
> what `AXIAM_HEALTHCHECK_CA_FILE` is for. A `fullchain.pem` carries the issuer
> and works.
>
> **Tests.** Ten unit tests over `resolve` with an environment map, and nine
> integration tests in `crates/axiam-server/tests/healthcheck.rs` against a real
> in-process rustls listener: the three anchor shapes above, the CA file alone,
> an absent file, an empty file, an unverifiable listener (there being no
> insecure switch), plus the two plaintext cases that file always had.
>
> **What the plan did not anticipate.**
>
> 1. **`AXIAM__SERVER__TLS__CERT_PATH` alone is the wrong condition, and using
>    it would have broken every Compose deployment.** The plan says to switch
>    the default when that variable is set. `docker/docker-compose.prod.yml:268`
>    sets it **unconditionally** and gates the listener on
>    `AXIAM__SERVER__TLS__ENABLED` (line 267, default `false`). Reading the path
>    alone would have moved every Compose deployment's probe to `https` against
>    a plaintext listener — the present defect, in the opposite direction, on a
>    stack that works today. The condition is both variables, and
>    `a_certificate_path_without_enabled_stays_plaintext` pins it.
> 2. **The certificate has to cover `127.0.0.1`.** The plan's default probes
>    that address; rustls verifies the server name, so the certificate needs an
>    IP SAN for it. A certificate issued for a DNS name fails the derived
>    default no matter how the anchors are resolved. The documentation says so
>    and names the remedy (`AXIAM_HEALTHCHECK_URL` plus a resolvable name);
>    the test PKI issues an IP SAN so the integration tests exercise the real
>    path rather than a hostname-verification bypass.
> 3. **The port was hardcoded.** The old default was literally
>    `http://127.0.0.1:8090/health`, so a deployment that moved
>    `AXIAM__SERVER__PORT` was probing the wrong port whatever its scheme. Both
>    schemes now read it. A deployment on the default port is unchanged, which
>    is the I4 twin.
> 4. **`tests/healthcheck.rs` was testing a copy of the code.** It called
>    `reqwest::blocking::get` itself, because the probe lived in `main.rs` and
>    `main.rs` cannot be linked from an integration test — so it would have kept
>    passing across this change without exercising a line of it. Both existing
>    tests now call `healthcheck::run`, which is also why the module is in the
>    library rather than the binary.
> 5. **The test listener needs `CryptoProvider::install_default`.** `rustls` in
>    this dependency graph reaches more than one provider feature, so
>    `ServerConfig::builder()` panics rather than choosing. `reqwest`'s rustls
>    backend is unaffected — it builds its own configuration — so this is a test
>    fixture concern only, and the panic is worth recording because it looks
>    like a verification failure in the output.

**The fix.** Two environment variables in the same single-underscore
namespace `healthcheck` already uses, documented next to
`AXIAM_HEALTHCHECK_URL` (`docs/deployment/rpi5-k3s.md:355` and the
deployment README):

- `AXIAM_HEALTHCHECK_CA_FILE` — a PEM bundle added with
  `reqwest::ClientBuilder::add_root_certificate` (the pattern at
  `crates/axiam-auth/src/secrets.rs:464`);
- when `AXIAM_HEALTHCHECK_URL` is unset and `AXIAM__SERVER__TLS__CERT_PATH`
  is set, the default becomes `https://127.0.0.1:<port>/health`, and, when
  `AXIAM_HEALTHCHECK_CA_FILE` is also unset, the probe trusts the server's own
  `AXIAM__SERVER__TLS__CERT_PATH` chain file (a local self-probe trusting the
  certificate it serves is sound). **Verify** that webpki accepts an
  end-entity certificate as a trust anchor before relying on that; if it does
  not, the default requires the CA file and the docs say so.

Never an "insecure" switch. **Tests.** A unit test over the URL/anchor
resolution function with an environment map; an integration test in
`crates/axiam-server/tests/` that starts a TLS listener with the test PKI
and runs the probe function against it, plus the I4 twin (plain HTTP
deployment unchanged). Compose: `docker/docker-compose.prod.yml:298` keeps
working unchanged. CHANGELOG: **Fixed**. Records: none.

### S-7 — explicit, name-constrained SAN issuance and a per-type KU/EKU profile (DF-001) — Opus 5

**Why fix, and why carefully.** The demo's whole PKI constraint — one trust
anchor, everything anchored in the AXIAM organization root — fails at exactly
one point: AXIAM cannot issue a certificate a TLS *server* can present, so
every listener certificate is signed offline. Closing that is worth a
feature. It is also the most security-sensitive item in this plan: a leaf
with `subjectAltName: DNS:login.example.com` signed by a tenant CA under the
organization root is trusted by **every** relying party that trusts that
root. A tenant administrator must not be able to mint one for a name that is
not theirs.

**Design.**

1. **A fourth certificate type**, `CertificateType::Server`
   (`crates/axiam-core/src/models/certificate.rs:29-36`). Only this type may
   carry SANs and only this type gets `EKU serverAuth`. It is not bindable to
   a service account (S-5's docs, `bind` handler: refuse `Server` with 400) and
   the device-auth path refuses it (`mtls.rs`), so a server certificate can
   never authenticate as a device.
2. **Explicit request fields, never the CSR's.** `CreateCertificateRequest`
   and `SignCertificateCsrRequest` gain
   `subject_alt_names: Option<Vec<SubjectAltName>>` with
   `{ "dns": … } | { "ip": … }` (URI and email deferred — no consumer). The
   CSR-carried extensions stay **refused** (`inspect_csr`), which keeps the
   Vault custodian consistent: with explicit fields both custodians issue the
   same thing, and Vault's `alt_names` / `ip_sans` are passed on the sign
   call.
3. **A name-constraint policy in the settings hierarchy**, in the shape the
   CIMD policy already uses (`models/settings.rs`, org baseline + tenant
   override, tighten-only): `pki.server_cert_allowed_names: Vec<String>` —
   DNS suffixes (`.lakeside.internal`) and IP CIDRs. Default **empty**, which
   means **`Server` issuance is refused** until an organization
   administrator lists names; a tenant override may only remove entries or
   narrow a suffix. Every requested SAN must match an entry; the CN must
   match too. This is the fence; Vault's role `allowed_domains` is a second
   fence, not the first.
4. **A per-type KU/EKU profile, applied on both leaf paths** (`leaf_params`):
   `User` / `Service` / `Device` → KU `digitalSignature` (+ `keyEncipherment`
   for RSA), EKU `clientAuth`; `Server` → KU as above, EKU `serverAuth`.
   Adding KU/EKU to existing types **narrows** what a leaf can be used for
   and never widens it; nothing issued today is used as a server certificate
   because nothing without a SAN can be. The migration note says exactly
   that, and that leaves issued before this change carry neither.
5. **Optional, recorded as D-7, not built here:** embed X.509
   `nameConstraints` in tenant signing CAs from the same policy, so the fence
   is in the chain and not only in AXIAM. Rejected for this round because a
   policy change would then mean re-issuing the CA.

**Cost, counted.**

| Item | Needed? | Where |
|---|---|---|
| Model | yes | `CertificateType::Server`, `SubjectAltName`, the profile function |
| Validator | yes | policy match, suffix and CIDR semantics, tighten-only interlock |
| Org-baseline interlock | yes | tenants narrow only |
| Admin UI | yes | settings card (org + tenant override) and the certificate form's SAN list — **Sonnet 5 sub-task S-7b**, after the API lands |
| New `AXIAM__*` key | no | it is a setting, not a config key |
| Schema | maybe | settings are a document; check whether the settings migration pattern needs a version bump |
| OpenAPI + registry | yes | two request DTOs, one enum variant, the settings DTO |
| Tests | yes | `sign_csr_test.rs` / `cert_test.rs`: `a_server_leaf_carries_the_requested_sans`, `a_san_outside_the_allow_list_is_refused`, `a_server_leaf_is_refused_while_the_allow_list_is_empty` (the I1), `a_tenant_override_cannot_widen_the_allow_list`, `a_device_leaf_carries_client_auth_and_no_san`, `a_server_certificate_cannot_be_bound` (`device_auth_test.rs`), `a_server_certificate_cannot_log_in_as_a_device` (`mtls_test.rs`); the Vault twin in `vault_pki_test.rs`; a **browser-shaped acceptance**: `rustls` client handshake against an actix listener presenting the issued leaf under the tenant CA under the root — the thing DF-001 says is impossible today |
| Docs | yes | `docs/pki/README.md`: the new type, the policy, the profile, the migration note; website `operate.ts` |
| Contract | yes, in C-0 | §27 DTO note; the SAN field is optional so existing SDK request types keep working |
| CHANGELOG | yes | **Added** (type, fields, policy) and **Changed** (profile) |
| Records | yes | new threat entry (tenant mints a certificate for a foreign name), Mitigated by the policy; §9 |

**I1.** With the allow-list empty, no `Server` certificate can be issued, and
every existing request (no `subject_alt_names`, existing types) produces a
leaf that differs from today's only by the KU/EKU profile.

### S-8 — client-certificate verification on the gRPC listener (DF-005) — Opus 5

**The fix.** Two flat variables in the namespace the gRPC TLS config already
uses (`tls.rs:1233-1238`):

- `AXIAM__GRPC_TLS_CLIENT_AUTH` — `off` (default) | `optional` | `required`
  (not `optional_self_signed`: that variant exists for RFC 8705 §2.2 on
  REST and has no gRPC consumer);
- `AXIAM__GRPC_TLS_CLIENT_CA_PATH` — PEM bundle; required when the mode is
  not `off`.

`build_grpc_rustls_server_config` (`tls.rs:1345`) replaces
`with_no_client_auth()` with the **same** `ReloadableClientCertVerifier`
the REST listener installs (`tls.rs:810`, loaded at `:1171-1181`), so anchors
hot-reload on both listeners through one mechanism. `tls_incoming`
(`crates/axiam-api-grpc/src/tls_incoming.rs:119`) captures the verified peer
certificate into the connection's extensions the way the actix side does,
and the auth interceptor (`middleware/auth.rs`) reads it for the `cnf` check
S-3 introduces. `required` is enforced at the handshake by rustls; nothing
in the interceptor needs to know the mode.

**What it does not do.** It does not bind the certificate to the principal
beyond `cnf`. Authenticating a gRPC caller **by certificate alone** (no
token) is a different feature and is out of scope; the token stays the
identity, the certificate is proof of possession and a network-level gate.

**Cost, counted.** Config: two constants, parsing, validation (`required`
without a CA path is a boot refusal, not a warning), docs rows
(`check-config-key-coverage.py`). Tests in `crates/axiam-server/tests/` and
`crates/axiam-api-grpc/tests/`: `required_refuses_a_handshake_without_a_client_certificate`,
`optional_accepts_both_and_exposes_the_certificate_when_present`,
`a_reloaded_anchor_is_honoured_on_the_grpc_listener`, I4 twin
`off_is_byte_for_byte_todays_handshake`. Docs: `docs/deployment/README.md`
gRPC TLS section; the `tls.rs:1270-1277` doc comment is rewritten — it
currently records the deferral. CHANGELOG: **Added**. Records: the T-234
follow-up recorded in that comment; the threat entry for gRPC gains the
control; §9.

**I1.** `off` produces today's `ServerConfig` — assert by comparing the
handshake behaviour, not the struct.

### S-9 — service-account principals on the management routes (DF-013) — Opus 5

**The fix.** The §27 management families switch from `AuthenticatedUser` to
`AuthenticatedPrincipal` and from `RequirePermission::check` to
`check_subject` (`authz.rs:207`), which already applies RBAC identically to
both principal kinds. **Families in scope:** resources, scopes, permissions,
roles (including the assignment routes), groups, service accounts,
certificates (`generate`, `sign_csr`, `bind`, list, revoke), webhooks.
**Deliberately out of scope for this round (D-5):** user self-service
(`/users/me`, MFA, sessions, password), organizations and tenants, settings,
`ca-certificates`, PGP, SCIM tokens, federation configuration — the routes
that mint long-lived secrets or change the trust posture keep requiring a
human-audience token until a second round argues each one.

The audit event for every converted route carries the principal kind, so a
service-account write is distinguishable in the log. Rate limiting: the
converted routes are already behind the authenticated-write limiter; no
change.

**Cost, counted.** Handler signatures (~70); a per-family positive test
(m2m token + granted role → 2xx) and negative test (m2m token, no role →
**403**, and the body says `authorization_denied`, not the audience
message); I4 twin per family (user token unchanged). A conformance-style
sweep test that walks `PERMISSION_REGISTRY` (`permissions.rs:24`) and asserts
every route in the in-scope families accepts both audiences and every route
out of scope still rejects `axiam:m2m` — so the boundary is pinned, not
implied. OpenAPI: security-scheme descriptions on the converted routes;
regenerate. Contract (C-0): §27 states which families accept a
service-account token. Docs: `docs/api/` authentication page; the operator
note at `token.rs:~1230` ("a device can no longer call user-facing routes")
is amended to say which routes a service account *can* call. CHANGELOG:
**Changed**. Records: threat entry for "service account holds user
credentials" (the finding's practical consequence) Mitigated; §9.

**I1.** A user token behaves exactly as today on every route. A
service-account token with no role assignment reaches nothing it did not
reach before — RBAC is default-deny, and the sweep test proves it.

### S-10 — a role assignment can be non-inheritable (DF-021) — Opus 5

> **EXECUTED — 2026-09-22, PR D, one commit.**
>
> **Shipped.** `inherit: bool` on `AssignmentScope`, `RoleAssignment` and
> `RoleSubjectAssignment`, default `true`; schema **v66**
> (`DEFINE FIELD IF NOT EXISTS inherit ON TABLE has_role TYPE option<bool>`,
> tripwire `Some(&66)`, plus a v66 test that it is additive DDL only). The engine
> clause is exactly the plan's, at `engine.rs:145`. The three
> `AssignRoleTo*Request` DTOs take `inherit: Option<bool>`; the three role-side
> listing DTOs carry `inherit: bool`, and the subject-side listings return
> `RoleAssignment`, which carries it. OpenAPI and the management registry
> regenerated.
>
> **Tests.** `engine.rs`: rows 9–11 through `applicable_role_ids` +
> `evaluate_grants`, and three property tests over every rule set of a
> three-node chain (12 candidate assignments, 4 096 subsets, three targets).
> `authz_engine_test.rs`: rows 9–11 decided through **both** `check_access`
> (`evaluate`) and `check_access_batch` under `Coalesced` (`evaluate_batch`),
> asserted equal item for item, plus the I1 twin, row 4 beside a
> non-inheritable allow, a group-inherited non-inheritable assignment, and the
> unassign-and-assign change. `grpc_authz_test.rs`: one test per row, each
> through `CheckAccess` and `BatchCheckAccess`. `role_assignment_scope_test.rs`:
> both 400s on all three routes, the I4 twin
> `an_assignment_without_the_field_inherits`, the flag accepted and listed on
> every path, and a recording `AuthzChecker` proving both halves of a change
> invalidate.
>
> **The clause was broken on purpose, twice, before the tests were trusted.**
> Dropping `a.inherit &&`: 3 unit tests red (rows 9 and 10, the row-10 witness),
> 4 end-to-end red (rows 9 and 10, the group row, the change row), 2 gRPC red
> (rows 9 and 10). Dropping the whole ancestor term: the same 3 unit tests and 12
> end-to-end tests red, including the pre-existing rows 3 and 4. Row 11 stays
> green under both, correctly — it is about the node itself.
>
> **What the plan did not anticipate.**
>
> 1. **`AssignmentScope` derived `Default`, and a derived default for a
>    `bool` is `false`.** Following the plan literally — add the field, keep the
>    derive — makes `AssignmentScope::default()` and `global()` produce
>    **non-inheritable** scopes, and any `AssignmentScope { resource_id, ..
>    Default::default() }` a silent "here and no further". `Default` is now a
>    manual impl through `default_inherit()`, the same function serde uses, and
>    an axiam-core test pins that every constructor and an absent field read
>    `true`.
> 2. **The existing property test cannot take the flag as a dimension.**
>    `adding_a_deny_can_never_widen_access` runs over `evaluate_grants`, which
>    receives role ids already filtered and never sees an assignment. The flag
>    lives one layer up, so the new property tests compose
>    `applicable_role_ids` with `evaluate_grants`. The plan's clause is made
>    executable in both directions: `false` on an allow never widens; `false` on
>    a deny **can**, asserted existentially with row 10 as the witness, and its
>    converse — making a deny inheritable — never widens. Table, tests, design
>    document, admin guide and website say the same thing.
> 3. **Group-inherited assignments reach the engine through a second SELECT.**
>    `get_user_role_assignments` reads direct and group edges in two statements;
>    the field had to be projected in both, and in the group and role-side
>    listings — four readers, not "the readers". A group end-to-end test pins it:
>    without the projection a non-inheritable group allow would cascade for every
>    member.
> 4. **The write stores `NONE` for `true`.** Only a departure from the default
>    is written, so a post-v66 inheritable edge is byte-identical to a pre-v66
>    one; the read maps absent to `true`.
> 5. **The global-role 400 needs a role read the plan did not mention.** It is
>    done only when `inherit: false` arrives with a resource; a missing role
>    falls through to the assignment's own error, as for an inheritable request,
>    and any other lookup error is returned rather than swallowed.
> 6. **`is_global` can be set after the assignment.** The write-time refusal
>    cannot stop `PUT /roles/{id}` making a role global later, which widens a
>    non-inheritable assignment of it to everywhere. That is what making a role
>    global does to every assignment of it, so it is documented as a residual in
>    the admin guide and T-285 rather than refused.
> 7. **Toggling is unassign-then-assign, verified rather than assumed.**
>    `has_role` is `UNIQUE(in, out)`: a second assign with the other value is a
>    409 and changes nothing (engine and REST tests). Both calls invalidate — the
>    plan's line numbers had moved, the claim had not — and a REST test with a
>    recording checker now pins it. The `grant.pre_assign` reactor payload
>    carries `inherit`, so a four-eyes rule sees what it approves.
> 8. **`deny-override-design.md` §6 had no "here and no further" item to move.**
>    It lists *deny exceptions* ("the subtree except this leaf"), which the flag
>    does not deliver and which stays out of scope; §6 now says so and
>    distinguishes the two. §3's sentence claiming `effect` on an assignment is
>    replaced with a note on why it was never needed, not deleted silently.
> 9. **There is no `docs/` authorization page.** Role assignment is documented
>    in `docs/admin/README.md`; the new subsection is there, linked from the
>    cascade paragraph and from the website.
> 10. **Records: two amendments and one new entry.** The entries that describe
>     the cascade as unstoppable are **T-16** and **T-87** ("cannot be revoked
>     on one child alone"); both gain the flag. T-227 is about *scope*
>     inheritance, which the flag does not change, and is left alone. The flag
>     brings its own hazards — read on one path and not another, stored where
>     ignored, a deny's reach narrowed silently — so it gets **T-285** on the
>     RBAC engine, High, Mitigated on arrival; `threatTop` 284 → 285.
>     `gen-threat-model.mjs` parses it (276 threats in the JSON, still nine
>     short of the documents — PR A's flagged reconciliation, not this one).
> 11. **The admin console does not offer the flag.** Its assignment types are
>     hand-written (`frontend/src/services/roles.ts`), not generated, so nothing
>     breaks and the new response field is ignored; the dialogs gain no control.
>     Recorded in the admin guide and the CHANGELOG as API-only for now.

**The proposal, kept, with two refinements.** The user's DF-021 asks for a
`non_inheritable` flag on a grant plus a write-time rejection of a
non-inheritable grant with no resource. Both are right. The refinements:

1. **The flag lives on the role assignment (`has_role`), not on the
   permission grant.** `effect: allow|deny` is a property of the
   role→permission `grants` edge (`schema.rs:1479-1482`); resource scope is a
   property of the subject→role `has_role` edge (`resource_id`,
   `tenant_scope`). Inheritance is about *where* an assignment applies, so
   the flag belongs beside `resource_id`. A role whose grants are denies,
   assigned non-inheritably at a node, denies at that node only — which is
   the semantics the finding wants for both effects.
2. **Positive name, defaulting to today:** `inherit: bool`, default `true`.
   A negative boolean (`non_inheritable: false`) is the kind of field that
   reads wrong in a manifest six months later.

**Engine.** One clause, in the one function
(`crates/axiam-authz/src/engine.rs:110-128`):

```rust
Some(rid) => rid == resource_id || (a.inherit && ancestor_ids.contains(&rid)),
```

Both `evaluate` (`:530-544`) and `evaluate_batch` (`:961`) call it, so one
change covers both transports and both paths — and both must be tested,
because [`deny-override-design.md`](deny-override-design.md) §5.1 records that
deleting the ancestor clause leaves all 72 unit tests green and only the
end-to-end tests catch it. `global_role_ids` (`:138-146`) is untouched: a
global role ignores resource scope by definition.

**Validation (the finding's second half, plus one more).** A 400 on:
`inherit: false` with `resource_id: null` (applies to nothing); `inherit:
false` on a role with `is_global: true` (the engine would ignore the flag,
so accepting it would be a silent no-op). Both are write-time refusals in
the three assign handlers.

**Precedence table.** The design document gains rows 9–11 and the property
gains a clause:

| # | Rules | Check on `unit-7` | Result |
|---|---|---|---|
| 9 | allow on `/fleet`, `inherit: false` | `unit-7` | **deny** (`no_grant`) — the allow stops at `/fleet` |
| 10 | deny on `/fleet`, `inherit: false`; allow on `/fleet` via another role, inheritable | `unit-7` | **allow**; on `/fleet` itself: **deny** (`denied_by_rule`) |
| 11 | allow on `/fleet/decommissioned/unit-7`, `inherit: false` | `unit-7` | **allow** — the node itself is always in scope |

Property: *adding a deny can never widen access* still holds — a
non-inheritable deny is a deny that reaches fewer nodes, never a widening of
any allow. The new clause: *setting `inherit: false` on an allow never widens
access; on a deny it can, and is therefore an unassign-and-assign, which
invalidates the subject's cached decisions like any unassign.* No update
endpoint is added: assignments are assign/unassign today, and the flag is
part of the assignment.

**Cache.** No key change (`decision_cache.rs:225-241` keys on subject,
resource, action, scope). Assign/unassign already invalidate
(`handlers/roles.rs:501,548,628,674,826,867`). Nothing new.

**Cost, counted.**

| Item | Needed? | Where |
|---|---|---|
| Schema | yes | **SCHEMA_V66**: `DEFINE FIELD IF NOT EXISTS inherit ON TABLE has_role TYPE option<bool>;` — absent means `true`, so no backfill; bump the tripwire at `schema.rs:3992` (`Some(&65)` → `Some(&66)`) |
| Core | yes | `AssignmentScope`, `RoleAssignment`, `RoleSubjectAssignment` (`models/role.rs:95-171`) gain `inherit: bool` with `#[serde(default = "default_true")]`; `axiam-authz` is `missing_docs`-opted-in, so every new field is documented |
| DB | yes | `relate_subject_to_role` (`role.rs:261-319`) sets the field; the readers decode it |
| REST | yes | the three `AssignRoleTo*Request` DTOs gain `inherit: Option<bool>`; the two validations; the assignment listing DTOs show the field |
| gRPC / AMQP | no | the engine is shared; assert it with one gRPC `CheckAccess` test per new row |
| OpenAPI + registry | yes | three request DTOs, listing DTOs; regenerate both |
| Tests | yes | `crates/axiam-authz/src/engine.rs` unit: rows 9–11; **`crates/axiam-authz/tests/authz_engine_test.rs`** end to end: rows 9–11 through both `evaluate` and `evaluate_batch`; `crates/axiam-api-rest/tests/role_assignment_scope_test.rs`: the two 400s and the I4 twin `an_assignment_without_the_field_inherits`; the property test in `engine.rs` extended with the flag as a dimension |
| Docs | yes | `docs/` authorization page; `deny-override-design.md` §2.2 rows 9–11, §3 (which today claims `effect` on a role assignment — it is not implemented, and the sentence goes), §6 (the "here and no further" case moves from out-of-scope to supported); website `authorization.ts` block |
| Contract | yes, in C-0 | §27 DTO note: optional field, default `true`; manifests may set it on a resource-scoped binding (ties into DF-011) |
| CHANGELOG | yes | **Added** |
| Records | yes | the authorization threat entries that mention hierarchy inheritance gain the flag's semantics; §9 |

**I1.** Every existing edge decodes as `inherit: true`; every existing test
passes unchanged; a request without the field is today's request.

### S-11 — the console resolves its upstream at request time (DF-026) — Sonnet 5

> **EXECUTED — 2026-09-22, PR C, commit 1 of 1.**
>
> **Shipped.** `docker/nginx.conf.template`: `resolver
> ${AXIAM_BACKEND_RESOLVER} valid=30s ipv6=off`, `resolver_timeout 5s` and
> `set $axiam_backend ${AXIAM_BACKEND_ORIGIN}`, once each in the `server`
> block; `proxy_pass $axiam_backend` in the three proxy blocks. The
> `proxy_ssl_*` lines are untouched, so T-217's unconditional verification
> against `AXIAM_BACKEND_SNI` holds in every rendering. New
> `docker/console-backend-resolver.envsh`, installed as
> `/docker-entrypoint.d/19-axiam-backend-resolver.envsh`. `Dockerfile.frontend`
> runs `nginx -t` on the rendered template in every build, and the new
> `.github/workflows/console-image.yml` builds the image and runs
> `scripts/e2e-console-resolver-check.sh` against it. The deployment guide has a
> console subsection.
>
> **Citations.** `nginx.conf.template:105/147/176` and
> `Dockerfile.frontend:155-158` were still exact on `249bd14`: no drift.
>
> **Verified here, on a real nginx** (Ubuntu's 1.24, not the image's 1.29; the
> image could not be pulled — Docker Hub answered 429 and ghcr's blob host is
> outside this sandbox's egress). The template was rendered by the upstream
> `20-envsubst-on-templates.sh`, fetched from `nginx/docker-nginx-unprivileged`,
> with a stub DNS server and echo backends on loopback. Main's template reproduces
> DF-026: `nginx -t` fails with `[emerg] host not found in upstream
> "axiam-server"`. The new one starts with the name unresolvable, answers `502`,
> then `200` once the name resolves, and follows the backend to a new address
> 30 s later with no reload, because the answer is reused for 30 s. For
> routing, fifteen request shapes plus a POST gave byte-identical results
> under both templates: encoded slashes, `..`, `//`, `;params`, bare `/api`,
> `/oauth2` (301) and `/oauth2-clients` (SPA). The hook was run under dash and
> bash against Docker, Kubernetes, mixed-family, empty and missing `resolv.conf`
> fixtures, and nginx accepts the mixed `a.b.c.d [v6]` form it emits.
> shellcheck and hadolint (2.15.1, the repo's `.hadolint.yaml`) are clean.
>
> **Not run here: the Docker half.** The sandbox's Docker daemon is not
> usable, so the image build, the build-time `nginx -t` and the start-order
> script were run by CI only.
>
> **What the plan did not anticipate.**
>
> 1. **A fixed `127.0.0.11` default is right on Docker only.** On Kubernetes
>    that address has nothing listening, so every proxied request would time out
>    at the resolver. The default is now read from the container's
>    `/etc/resolv.conf` by an entrypoint hook, the same source the old
>    startup-time lookup used: `127.0.0.11` under Docker, the `kube-dns`
>    ClusterIP under Kubernetes. An operator-set `AXIAM_BACKEND_RESOLVER`
>    always wins, and `127.0.0.11` remains only as the last resort for a
>    `resolv.conf` with no nameserver, because an empty `resolver` directive
>    would stop nginx from starting. There is deliberately no `ENV` default: it
>    would override the lookup.
> 2. **nginx's resolver ignores `search` domains.** The plan documents the
>    resolver for Kubernetes but not the origin. Even with the right resolver,
>    `http://axiam-server:8090` does not resolve there, so the guide now says
>    the origin must be the FQDN. The shipped manifests are unaffected: the
>    ingress routes `/api`, `/oauth2` and `/.well-known` straight to the
>    server, and `k8s/frontend/deployment.yml` sets no `AXIAM_BACKEND_*`.
> 3. **`set` once, not three times.** A server-level `set` runs in the
>    server-rewrite phase for every request, so one line serves the three
>    blocks and there is one place to change.
> 4. **No CI job built the frontend image on a pull request.** Only
>    `release.yml` built it, on a tag, as `ci.yml`'s docker-context comment
>    already notes, so "the frontend image build runs `nginx -t`" would have
>    run at release time only. The `nginx -t` step is in the Dockerfile anyway
>    (every build, release included), and the new workflow is the PR-time build
>    that §3 calls "its own CI path filter", which did not exist either. The
>    step runs as uid 101 over a tmpfs `/tmp`, because `nginx -t` creates the
>    base image's temp directories under `/tmp` and they must not land in the
>    image. It renders through the real hooks, not a hand-written envsubst, and
>    greps its patched `nginx.conf` so a base image that moved its include
>    line fails instead of testing the stock `default.conf`.
> 5. **`docker-compose.e2e.yml` has no console.** The Playwright suite serves
>    the SPA from `vite preview`. Adding the console there would mean building
>    the frontend image inside the E2E job, and `depends_on` ordering is not
>    a start-order test. The scenario is a dedicated script instead, plain
>    `docker` on a user-defined network with an echo stand-in for the
>    backend: the console starts first, `/api`, `/oauth2/` and `/.well-known`
>    answer `502`, the backend appears and they answer `200`, seven URI shapes
>    arrive unchanged, the backend is recreated on a new IP and is found with
>    the console's `StartedAt` unchanged, and an explicit resolver is rendered
>    verbatim (the I4 twin).
> 6. **`.dockerignore`** excludes `docker/` and re-includes files by name, so
>    the hook needed its own negation; `check-docker-context.py` confirms it.
> 7. **`resolver_timeout 5s`.** nginx's default of 30 s would hold every
>    proxied request for 30 s behind an unreachable resolver.
>
> **Records: none, verified.** No threat entry names the console's upstream
> resolution. The DNS trust is the same as before, since the old startup-time
> lookup asked the same server; only the time of the question changes. On an
> `https` origin a spoofed answer still fails the handshake (T-217 is
> unchanged). On a plaintext origin a spoofed answer was already enough to
> read the traffic, which is T-217's own residual. Axiam.json, the two STRIDE
> documents and `gen-threat-model.mjs` are not touched. `threatTop` stays 284.
>
> **Found, not fixed — outside this PR.** `k8s/frontend/deployment.yml` sets
> `readOnlyRootFilesystem: true` and mounts no volume at
> `/etc/nginx/conf.d`. The stock `20-envsubst-on-templates.sh` logs
> `/etc/nginx/conf.d is not writable` and returns without rendering. So on
> Kubernetes the console most likely serves the base image's own
> `default.conf`: no SPA fallback, none of the template's security headers,
> no proxying. Read from the entrypoint source, not observed on a cluster.

**The fix.** In `docker/nginx.conf.template`, the three blocks
(`:105`, `:147`, `:176`) become:

```nginx
resolver ${AXIAM_BACKEND_RESOLVER} valid=30s ipv6=off;
set $axiam_backend ${AXIAM_BACKEND_ORIGIN};
proxy_pass $axiam_backend;
```

with `AXIAM_BACKEND_RESOLVER` defaulting to `127.0.0.11` (Docker's embedded
DNS) in `docker/Dockerfile.frontend:155-158`, and documented for Kubernetes
(the cluster DNS service IP, or `kube-dns.kube-system.svc.cluster.local`).
`proxy_ssl_name ${AXIAM_BACKEND_SNI}` is unchanged. Because a variable
`proxy_pass` passes the original URI unmodified, and the current form has no
URI part either, routing is identical — assert it. The `resolver` line goes
in the `server` block once, not three times.

**Tests.** The frontend image build runs `nginx -t` against a rendered
template with the defaults (add the step to `Dockerfile.frontend`, before
`USER 101` if it needs root, else in the e2e workflow); the e2e compose
(`docker-compose.e2e.yml`) starts the console **before** the server and
asserts a 502, then a 200 once the server is up — the finding's scenario.
`scripts/check-docker-context.py` stays green. Docs: `docs/deployment/README.md`
console section. CHANGELOG: **Fixed**. Records: none.

---

## 5. DF-021 — the alternatives, and why the flag wins

The user proposed the flag explicitly to avoid ABAC or ReBAC. The
alternatives that were weighed, so the choice is on record:

| Option | What it is | Why not |
|---|---|---|
| **Deny layer at the descendant tier** (what the demo does today) | Grant at ancestors; add a deny role at every apartment | Grows with the tree; encodes the headline rule as a workaround; every new apartment needs a deny |
| **Type-scoped assignments** (`applies_to_resource_type: "building"`) | The assignment applies only to nodes of a named type | It is ABAC with one attribute, and the next request is for two; the precedence table would need a type axis |
| **Depth-limited inheritance** (`max_depth: 1`) | The assignment reaches *n* levels down | Strictly more general than the flag, and strictly harder to reason about: a reviewer must know the tree's depth at every node to read a policy |
| **`inherit: bool` on the assignment** (chosen) | The assignment applies at its node, and to descendants only if `true` | One boolean, one engine clause, the precedence table gains three rows and loses none; every existing policy keeps its meaning |

One thing the flag does **not** give: "this subtree except one leaf". That
stays out of scope, as `deny-override-design.md` §6 already rules, and the
answer stays "narrow the deny". The demo's model needs the flag and not the
exception, which is what makes it the right first step.

---

## 6. SDK tasks — contract 1.50 and the fan-out

Every SDK finding is generalised to all eleven SDKs, as the user asked and as
the matrix in §1 supports: none of DF-008, DF-009, DF-010, DF-011 or DF-012 is
Rust-specific.

### C-0 — contract 1.50 (`axiam` repo, after PR G) — Opus 5

Text first, before any port; the fan-out rules in §8 forbid writing an SDK
against a draft. Amendments:

1. **§1 locked vocabulary** — two new rows, resolving the contradiction the
   fourth agent found between §1's closed list and §10.3's normative
   expectation: `authenticate_device` (REST-only, §6.1; the C++ name is the
   one that exists, so it is the one that spreads) and
   `validate_token` / `introspect_token` (gRPC-only, §10.3; the operation
   names §10.3 already uses). §1.1's "the first operation served only over
   gRPC" sentence is amended to "the first three".
2. **§5.2 rule 1** — the acting-tenant helper moves from **MAY** to
   **SHOULD**, with a shape: a builder option `with_acting_tenant(tenant_id)`
   and a rebind helper `acting_tenant(tenant_id)` on an existing client; the
   header is sent only when set; the helper is documented as meaningful only
   for an `organization_level` principal; rule 4's `reachable_tenant_ids`
   restriction already binds it. The §5 callout ("`X-Tenant-ID` is not the
   acting-tenant header") stays and gains a pointer.
3. **§6.1** — `authenticate_device()` is the operation, returning
   `{ access_token, token_type, expires_in }`; it MUST be reachable only on a
   client configured with a certificate; and, after S-3, the note that the
   token is certificate-bound and §10.1 rule 9 applies to it.
4. **§27.0 exclusion table** — the `/admin/bootstrap` row the registry has
   and the prose lacks, with the three outcomes (201, 403, 409) a
   provisioning tool must handle. **No helper** (D-8): the registry's reason
   stands — no tenant-scoped client can hold the credential — and a
   documented exclusion is what the finding asked for as its second option.
5. **§27.6** — the manifest spec is made explicit where it was only listed:
   `resources[].metadata` (object); `groups[].roles[]` entries are either a
   role key **or** `{ role, resource, inherit? }` (resource-scoped binding,
   `inherit` from S-10); a `service_accounts` section (`name`, `description`,
   `roles[]` in the same two shapes). **§27.5 decides what `apply` returns
   for a newly created service account's secret** — the contract task reads
   the imperative `create` contract and records the rule (most likely: the
   same one-time return, redacted in `Display`, exactly as the imperative
   call). `webhooks` stays listed and unimplemented; this plan does not take
   it.
6. **§27.10** — the per-SDK posture table gains columns for the three §27.6
   additions **and** records the tier gap the reading found: PHP, Swift, C
   and C++ manifests have no `users` and no `scopes`. That is a fact the
   table currently hides behind "all eleven implement it".
7. **§10.3** — the test rules become satisfiable; no wording change beyond a
   pointer to §1's new rows.
8. **§27 DTO notes** for the optional fields S-4 (status), S-7 (SAN, type),
   S-9 (which families accept `axiam:m2m`) and S-10 (`inherit`) introduced.

Re-vendor note in the same commit: the eleven SDKs re-sync `CONTRACT.md`,
`openapi.json`, `management-registry.json` and `proto/` from **this** commit.
Contract **1.50**.

### C-1 — Rust SDK reference implementation — Opus 5

Rust is the reference because the demo consumes it and because the
maintainer works in it. Scope, against contract 1.50:

- **Acting tenant** — `AxiamClient::builder().with_acting_tenant(Uuid)` and
  `client.acting_tenant(Uuid)`; the REST layer sends `X-Axiam-Tenant` when
  set; the gRPC interceptor sends the metadata twin **only if the server
  reads it there** (check `crates/axiam-api-grpc/src/middleware/auth.rs`
  first; if it does not, the contract says REST-only and the SDK does not
  invent a metadata key). Restricted to `reachable_tenant_ids` when the login
  result carries it (§5.2.3 rule 4).
- **`authenticate_device()`** in `rest::auth`, reachable only when
  `with_client_cert` was called; returns the §6.1 shape; the
  `examples/device_login.rs` (RFC 8628) is left alone and a
  `device_mtls_login.rs` example is added so the two stop being confused.
- **gRPC** — `validate_token` and `introspect_token` wrappers in
  `src/grpc/client.rs`, reading `cnf` per §10.3 rule 1.
- **Manifest** — `ResourceSpec.metadata`, the two-shape group binding,
  `ServiceAccountSpec`; `plan()` diffs them; `apply()` orders them per §27.6
  rule 5.
- **`inherit`** on the three assign requests and in the manifest binding.
- **`JwksVerifier` and `cnf`** — verify that a device token carrying
  `x5t#S256` is refused without evidence and accepted with it (contract
  §10.1 rule 9); if the verifier ignores `cnf` today, that is a bug fixed in
  this task, not a new feature.
- README conformance statement; tests per §8; `CHANGELOG.md`.

### C-2 … C-11 — ten ports — Sonnet 5, effort `high`

| Task | SDK | Scope |
|---|---|---|
| C-2 | TypeScript | full (REST + gRPC + manifest) |
| C-3 | Python | full |
| C-4 | Java | full |
| C-5 | C# | full |
| C-6 | PHP | full; manifest is the flat-entity tier (§27.10 records it) |
| C-7 | Go | full; the `TokenService` client leaves `internal/` |
| C-8 | Kotlin | REST + manifest (no gRPC transport) |
| C-9 | Swift | REST + manifest, flat-entity tier |
| C-10 | C | REST + manifest, flat-entity tier; **the README claim at `:193` becomes true** (§1.8) |
| C-11 | C++ | REST + manifest, flat-entity tier; `authenticate_device()` already exists — align its return type with §6.1 and add the `cnf` note |

Each port: read the SDK's `CLAUDE.md`, README conformance section and CI
workflow before touching it; implement the reference's behaviour in the
language's own shape; the tests in §8 rule 7; `declines` any piece it cannot
implement, in §27.10 / the §5.2 table, with the reason.

### C-12 — cross-SDK conformance review — Opus 5

§28.11's form: one row per divergence, contract **1.51**, the posture
tables filled from merged code, README statements checked against code
(F-28-02's lesson). Evidence file `claude_dev/sdk-dogfooding-conformance-review.md`.

---

## 7. Decisions

| Id | Item | Question | Chosen | Rationale |
|---|---|---|---|---|
| D-1 | S-6a | Accept the documented-but-wrong secret names as aliases? | **No.** Fix the names; warn on the legacy spelling | Two names for one secret is the trap the finding describes |
| D-2 | S-6b | Parse a full DN in `subject`? | **No.** Bare CN or a single `CN=` RDN; refuse the rest | The certificate has one CN; a DN parser is scope with no consumer |
| D-3 | DF-003 | Widen `has_role` uniqueness to `(subject, role, resource)`? | **Maintainer decision, not in this plan** | Inverts a pinned invariant; SurrealDB cannot express the partial index that would keep "one global assignment" unique alongside it; the demo does not need it yet — but a hierarchical model will |
| D-4 | DF-004 | Mirror management on gRPC? | **Defer** | Large; REST works; the listener needs S-8 first; `ReactorAdminService` is the precedent when it is taken |
| D-5 | S-9 | Which routes accept a service-account token? | The §27 management families; **not** self-service, org/tenant, settings, CA, PGP, SCIM, federation | Routes that mint long-lived secrets or change trust posture keep a human audience until argued one by one |
| D-6 | DF-006 | Refresh tokens for devices? | **Decline** | A refresh token is a second bearer credential per device, stored server-side, rotated, revocable — for a device that already holds the stronger credential (its key) and can prove possession on demand. The handshake cost is Ed25519 once per lifetime. With S-3 the access token is certificate-bound; a refresh token would need the same binding to be no weaker. If the fleet cost is real, the right knob is a **device access-token lifetime** setting, which is a later, smaller change |
| D-7 | S-7 | X.509 `nameConstraints` in tenant CAs from the allow-list? | **Not this round** | A policy change would re-issue the CA; the AXIAM-side fence is enough to close the finding; recorded for the next PKI pass |
| D-8 | DF-010 | Expose `/admin/bootstrap` in the SDKs? | **No.** Document the exclusion and the status codes in §27.0 | The registry's reason stands; the finding's own second option |
| D-9 | DF-024 | Raise `login_per_min`? | **No.** | G7 decision; the 429 already names itself; the unlimited device login is the real defect (S-2) |
| D-10 | S-10 | Field name | `inherit`, default `true` | Positive booleans survive manifests |

### 7.1 A maintainer task this plan does not take

The `has_role` key (D-3). If the domo demo, or any consumer, needs one
subject to hold one role at two resources, the options are: a per-resource
group (the workaround), or the wider key with a migration that first
verifies no subject currently holds a role both globally and at a resource.
The second is a design decision with a data migration; it deserves its own
document.

### 7.2 Also out of scope, deliberately

- `webhooks` in the manifest (§27.6 lists it; no finding asks for it).
- Certificate-only authentication on gRPC (S-8 gates and binds; it does not
  authenticate by certificate).
- The `users` / `scopes` manifest tier in PHP, Swift, C and C++ — recorded in
  §27.10 by C-0, fixed when a consumer needs it.
- Re-running the FAPI and Basic OP conformance suites: none of the server
  tasks touches `/oauth2/*`, so the 2026-09-11 result stands; **say so in
  each PR rather than claim a run**.

---

## 8. SDK fan-out rules

These are [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md)
§13's rules, restated because they bind C-1 … C-11:

1. **Server and contract first**, merged, before any SDK branch.
2. **One branch, one PR per SDK repository**, named `feat/contract-1.50`,
   each re-vendoring `CONTRACT.md`, `openapi.json`, `management-registry.json`
   and `proto/` from the C-0 commit, and passing that SDK's own §27
   codegen-diff job, its conformance suite, its linter and its full test
   suite the way its CI runs them.
3. **Read each SDK's `CLAUDE.md`, README conformance section and CI workflow
   before touching it.** Eleven idiomatic implementations beat one shape
   transliterated eleven times.
4. **Never tag or publish.** `scripts/mass-tag.sh` is the maintainer's. Never
   change an `alg` pin, a TLS policy, or §5 rule 3.
5. **`declines`, with the reason,** in the contract's per-SDK table for any
   piece an SDK cannot implement. Never a silent omission.
6. **`CHANGELOG.md` under `[Unreleased]`** in every repository touched.
7. **Tests every port ships:** the acting-tenant header is sent when set and
   **absent when not** (the I4 twin); `authenticate_device()` is unreachable
   without a certificate; the gRPC wrappers read `cnf`; the manifest round-trips
   `metadata`, a resource-scoped binding with `inherit: false`, and a service
   account; `plan()` on an already-applied manifest is empty.
8. **"The toolchain is unavailable" is a claim about a search**
   (§13.1's lesson: two of three such claims were wrong). Search twice.

Fan-out record: an eleven-row table, filled in as PRs open, appended to this
document under §8.1 by the executing sessions.

---

## 9. After each item: keep the model honest

In the **same commit** as the code, every time, exactly as
[`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) §11
prescribes:

1. `ThreatDragonModels/Axiam/Axiam.json` — the source of truth. New entries
   for S-1 (cross-tenant issuance), S-2 (handshake amplification), S-7
   (foreign-name issuance) and, where no entry exists, S-3, S-8, S-9; numbers
   are the next free ones, never reused; `threatTop` is never lowered.
2. `claude_dev/threat-model-stride.md` — the row, the detail block, the
   counts, §6's register, §7's coverage tables.
3. `claude_dev/threat-modeling-and-security.md` — prose and counts.
4. `node website/scripts/gen-threat-model.mjs` — run to confirm the model
   parses, note the headline line in the commit message, **revert the
   generated files**.
5. `claude_dev/roadmap.md` — a **Phase 22, "Dogfooding remediation
   (axiam-domo-demo DF-001 … DF-027)"**, one `### T22.n` per task in this
   plan with its model in the title, in the house form, marked as it lands.
6. This document — an `EXECUTED` block at the head of each task section:
   what shipped, which tests, what the plan did not anticipate.

---

## 10. Feedback to the findings document

The executing session does not edit `axiam-domo-demo`; the maintainer does.
What the reading established, for the file's own `resolved` /
`confirmed` discipline:

| Entry | Suggested change |
|---|---|
| DF-001 | Reproduction is wrong (a CSR asking for the extensions is refused with 400, `sign_csr_test.rs:434/471/520`); the gap — no SAN/KU/EKU on any issued leaf, no field to request them — stands. Reword, keep severity |
| DF-003 | **Incorrect**: `has_role` is `UNIQUE(in, out)` and a repeat is a 409 (`role_assignment_scope_test.rs:582`). Replace with the real limitation: a subject cannot hold one role at two resources (§1.2, D-3) |
| DF-004 | Partially incorrect: `ReactorAdminService` is a gRPC management surface; the missing part is users/roles/resources |
| DF-013 | Add: the plumbing exists (`AuthenticatedPrincipal`, `check_subject`, service-account roles); only the extractor choice is narrow |
| DF-014 | Add: `cnf` exists and is minted for OAuth2 mTLS clients; the device path alone omits it |
| DF-024 | The 429 carries `Retry-After` and `rate_limit_exceeded`; check `domo-bootstrap`'s status mapping. The default is a recorded decision (G7) |
| **DF-028 (new)** | `POST /api/v1/auth/device` has no rate limiter (`server.rs:261`); severity medium; fixed by S-2 |
| **DF-029 (new)** | `axiam-c-sdk/README.md:193` advertises `POST /api/v1/auth/device`; no symbol implements it; fixed by C-10 |

---

## 11. Verification, the way CI does it

```bash
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings      # per crate touched; workspace-wide before the PR
cargo test  -p <crate> --lib
cargo test  -p <crate> --test <file>                       # the files each task names
scripts/check-crate-layering.py
scripts/check-doc-links.sh
scripts/check-config-key-coverage.py
# PRs A, D, G, and any task that changes a DTO or a response line:
apt-get install -y protobuf-compiler                       # absent in a fresh sandbox
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > sdks/openapi.json
python3 scripts/check-spec-digest.py
python3 scripts/gen-management-registry.py --check
```

- `--no-default-features` where libxml2 is absent (CI's "Build (SAML off)").
- `cargo clean` **between** tasks, never during one; the sandbox disk is
  finite and a full workspace `cargo test` is not.
- Capture cargo's own exit code — redirect to a log and test `$?`, never
  `| tail`.
- Never skip, disable or quarantine a test. Every negative test gets its
  **I4 twin**: a client, a deployment or a token shaped as today behaves as
  today. No credential in a panic message or a derived `Debug`.
- The FAPI 2.0 and Basic OP conformance results of 2026-09-11 stand
  (§7.2); say so in the PR, do not claim a run.

---

## 12. The kick-off prompt for the executing sessions

One prompt, parameterised by PR letter. The first session runs PR A on
Opus 5; later sessions substitute the letter and the model this document
assigns. A session takes **one PR**, and ends with it pushed and green.

```
Read claude_dev/dogfooding-findings-fix-plan.md in full before doing anything
else. You are executing pull request <LETTER> of that plan — its tasks are
listed in §3 and specified in §4 (server) or §6 (SDKs). Nothing outside that
PR's tasks is in scope; if a task turns out to need something the plan did not
anticipate, record it in an EXECUTED block at the head of the task's section
and keep going.

Rules that bind this session:
- Boot SAGE (`sage_inception`) first if the MCP is connected; if not, say so
  once and continue.
- Work on branch <BRANCH from §3>, cut from main. One commit per task, in the
  order §3 gives. Signed commits.
- Before writing code for a task, read the files the task cites at the lines
  it cites. The plan was validated against main @ 2fc0193; if main moved,
  re-validate the citations you touch and note any drift in the EXECUTED block.
- Every task ships the tests it names, its I1 (the new behaviour is absent
  when the flag/policy is off) and every negative test's I4 twin, the docs it
  names, a CHANGELOG entry under [Unreleased], and the §9 records — threat
  model (Axiam.json + the two stride documents, gen-threat-model.mjs run and
  reverted), roadmap Phase 22 entry, EXECUTED block — in the same commit.
- Run §11's gates per crate, with `cargo clean` between tasks; regenerate
  sdks/openapi.json and management-registry.json only where the task says so,
  and only on a clean `git status`. Capture cargo's exit code, never `| tail`.
- Never skip, disable or quarantine a test. Never claim a conformance run
  that did not happen. Never tag or publish anything.
- When the PR is open, subscribe to it and drive it to green; reply to
  review threads on the PR, not here.

Start by printing the task list for PR <LETTER> with the files each task
touches, then begin with the first task.
```

**References**

- [`claude_dev/remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) — §11 records, §12 gates, §13 fan-out rules
- [`claude_dev/issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) — the "cost, counted" form
- [`claude_dev/mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md) §2 — the model rule
- [`claude_dev/deny-override-design.md`](deny-override-design.md) — §2.2 precedence table, §5.1 the ancestor-clause warning, §6 out of scope
- [`claude_dev/rate-limit-posture-decision.md`](rate-limit-posture-decision.md) — G7
- [`claude_dev/decision-cache-decision.md`](decision-cache-decision.md) — cache key and invalidation levels
- [`claude_dev/crate-layering.md`](crate-layering.md) — for S-3's thumbprint helper
- `sdks/CONTRACT.md` §1, §5.2, §6.1, §10.3, §27.0, §27.6, §27.10, §28.11
