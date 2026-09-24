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

> **EXECUTED — 2026-09-23, PR G, one commit** (branch `feat/pki-leaf-profile`, cut
> from `9cc472f`, the merge of #494).
>
> **Shipped.**
>
> - **The type and the field.** `CertificateType::Server`, plus
>   `subject_alt_names: [{"dns"|"ip": …}]` on both leaf request DTOs and both
>   domain inputs.
> - **The fence.** `axiam_core::models::server_names` holds the matcher, the
>   entry parser, `covers` / `intersect` and `check_leaf_names`. Both leaf
>   paths call `check_leaf_names` before the CA lookup.
> - **The setting.** `server_cert_allowed_names` sits in `CertificatePolicy`,
>   `SetOrgSettings` and `TenantSettingsOverride`. The plan's
>   `pki.server_cert_allowed_names` is spelled
>   `certificate.server_cert_allowed_names` in the resolved view, because
>   `certificate` is the group this model already had for issuance
>   constraints. It rides the same four functions every override uses:
>   `validate_tenant_override`, `clamp_overrides_to_org`, `effective_settings`
>   and `diff_against_org`. The org check is in `validate_org_settings`.
> - **The profile.** `LeafProfile::for_leaf` reaches `leaf_params` and the
>   Vault body.
> - **Refusals.** `Server` is refused at `bind` (400) and in
>   `DeviceAuthService::authenticate_der`.
> - **Schema v67.**
> - OpenAPI and the management registry are regenerated.
>
> **Tests.**
>
> - `server_names` unit tests: 16.
> - Settings interlock unit tests: 7.
> - `settings_org_propagation_test`: 2, the stored baseline and a shrinking
>   baseline.
> - `cert_test`: 6, the five the plan names plus
>   `the_profile_is_per_type_and_per_key_algorithm`.
> - `sign_csr_test`: 4 twins.
> - `vault_pki_test`: 4 twins.
> - `mtls_test::a_server_certificate_cannot_log_in_as_a_device`.
> - `device_auth_test`: `a_server_certificate_cannot_be_bound` and
>   `a_server_certificate_is_issued_over_rest_only_for_allow_listed_names`.
> - `settings_test`: one wire-level test for the tighten-only rule.
> - `axiam-server/tests/server_leaf_profile.rs`: the browser-shaped
>   acceptance, its Device twin, and the client-certificate verifier refusing
>   a Server leaf.
>
> Nine deliberate mutations each turned a named test red; the PR description
> lists them.
>
> **What the plan did not anticipate.**
>
> 1. **`sign-verbatim` ignores `alt_names` and `ip_sans`.** Design item 2 says
>    Vault's `alt_names` / `ip_sans` "are passed on the sign call". They would
>    be dropped. Measured against a real Vault 1.18.3 dev server: SANs come
>    from the CSR and nowhere else (`use_csr_sans` is hard-wired on), while
>    `key_usage` and `ext_key_usage` apply when the CSR requests neither. So:
>    - On `generate`, the admitted names go **inside the CSR AXIAM builds**.
>    - On `sign-csr`, a `Server` request under a remote signer is **refused**,
>      because no channel for its names exists: the CSR may not carry them,
>      and the body parameter is ignored. A Vault role with
>      `use_csr_sans=false` would be one, but it needs a new config key the
>      plan excluded. It is recorded here as the follow-up, not built.
>    - Every Vault call now states the profile and `exclude_cn_from_sans`.
>      T-268's "documented rather than observed" residual is amended with the
>      observation.
> 2. **`cert_type` has a database assertion.** v1 lists three values, so a
>    `Server` row would have failed at the insert, after signing. That makes
>    the plan's "Schema: maybe" a **yes**: v67 restates the assertion with four
>    values (`OVERWRITE`, as v46 did for `key_custody`) and adds
>    `security_settings.cert_server_allowed_names`, `option<array<string>>`.
>    The tenant override needs no DDL, because it lives in `overrides_json`.
>    No row is rewritten.
> 3. **Clearing is the wrong clamp for a list.** `clamp_overrides_to_org`
>    clears a stale override so the tenant tracks the baseline. That is right
>    for scalars, where the baseline is the stricter value, but wrong here.
>    Take a tenant that kept only `.a.x` out of `[.a.x, .b.x]`: if the
>    organization drops `.a.x`, clearing would hand the tenant `.b.x`, which
>    it had removed. The override is narrowed to the **intersection**
>    instead, and `effective_settings` computes the same intersection on every
>    read, so no path sees an uncovered entry even when the clamp did not run.
>    Every pair of entries is either nested or disjoint, so the intersection
>    is exact.
> 4. **The CIMD precedent argues the other way for this list.** CIMD's lists
>    are deliberately unordered, because they name the tenant's own resources.
>    This one names what the organization root vouches for, so it is ordered
>    by inclusion. The interlock is reused; the unordered exemption is not.
> 5. **The Vault generate path diverged from the in-process path.** Before
>    this change it sent no usage parameters, so Vault leaves carried Vault's
>    default KU with no EKU, while caller-CSR Vault leaves carried none. The
>    test `a_generated_leaf_still_sends_no_usage_parameters` pinned that and
>    is renamed `a_generated_leaf_states_the_same_profile_as_a_caller_csr`. In
>    `sign_csr_test`, one assertion ("a leaf carries no key usage extension")
>    now asserts the profile. Both are behaviour changes this task makes on
>    purpose, not weakened tests.
> 6. **`optional_self_signed` downgrades rather than refuses.** Under that
>    policy the REST verifier accepts a certificate that fails the chain
>    check, including one that fails only on EKU, and classifies it
>    `SelfAsserted`. Device login and `tls_client_auth` both refuse
>    `SelfAsserted`, so the separation holds; a test pins the classification.
> 7. **Citation drift** against `9cc472f`, all located by content:
>    - `models/certificate.rs:29-36` was exact.
>    - `inspect_csr` is at `ca.rs:1084`, and the refused list at `:1144-1157`
>      (the plan said `:1129-1143`).
>    - The `sign_csr` refusal is at `cert.rs:586-597` (plan: `:508-519`), and
>      its rationale at `:548-560` (plan: `:471-483`).
>    - `leaf_params` is at `:792-806` and its "follow-up" comment at
>      `:777-791` (plan: `:712-726` and `:698-711`).
>    - `CreateCertificateRequest` is at `handlers/certificates.rs:28` (plan:
>      `:25`) and `SignCertificateCsrRequest` at `:123` (plan: `:90`).
>    - A stray doc comment, `parse_issued_leaf`'s, sat above `leaf_params`.
>      It is moved back.
>
> **Records.**
>
> - **T-288** is on `Certificate issuance` in the PKI diagram: Spoofing, High,
>   Mitigated. It is in `Axiam.json` (`threatTop` 287 → 288) and in both STRIDE
>   documents: 288 threats, 275 mitigated / 13 open; Spoofing 70, High 135,
>   PKI diagram 30.
> - **T-268** is amended.
> - `gen-threat-model.mjs` reports *"threatModel.ts: 9 diagrams, 279 threats
>   (266 mitigated, 13 open)"*, still nine behind the documents, which is not
>   this task's to reconcile. The generated files were reverted.
> - `threat-modeling-and-security.md`'s "Coverage by area" table was already
>   stale before this wave (PKI 26) and is left for the same reconciliation.
> - Roadmap **T22.14**.
> - CHANGELOG entries under **Added** (type, fields, policy, v67) and
>   **Changed** (profile, with the migration note).
> - **D-7** (`nameConstraints` in tenant CAs) is recorded as deferred, in
>   T-288's residual and in the PKI guide.
> - No `/oauth2/*` route changed, so the FAPI 2.0 and Basic OP results of
>   2026-09-11 stand (§7.2).
>
> **Next step: S-7b** (Sonnet 5), the admin UI. It needs a settings card for
> `server_cert_allowed_names`, with the org baseline and the tenant override,
> and a `Server` type with a SAN list on the certificate form. The console's
> types are hand-written, so nothing breaks meanwhile: the form simply does
> not offer `Server` yet.

> **EXECUTED — S-7b, 2026-09-23, PR G2, commits 1 and 2 of 5** (branch
> `feat/console-leaf-profile`, cut from `f210676`, the merge of #495; the task
> §3 does not list, taken as the console follow-up this block names).
>
> **Commit 1 — the certificate form.**
>
> - **Shipped.** `CertificateType` gains `Server`; `SubjectAltName` is typed as
>   the server deserialises it (`{dns}` | `{ip}`, externally tagged, snake
>   case). Both dialogs share one `CertificateTypeSelect` and, for `Server`
>   only, one `SubjectAltNamesField`: one row per name, a DNS/IP select, add and
>   remove. `subjectAltNamesFromRows` (`services/certificates.ts`) is the whole
>   client-side rule: at least one row, no blank row, kind `dns` or `ip`,
>   surrounding whitespace trimmed as the subject already was. Nothing else is
>   judged in the browser — no suffix match, no wildcard or IDNA or trailing-dot
>   or IPv4-mapped check — and the tests pin that by sending each of those
>   through unchanged. The server's `400` reaches the dialog through the
>   existing `getApiErrorMessage` path, verbatim.
> - **I4.** A `User`, `Service` or `Device` request carries no
>   `subject_alt_names` key at all, not an empty one — asserted on the key set,
>   because `toHaveBeenCalledWith` treats an `undefined` property as absent and
>   would pass either way. A type switched away from `Server` drops its names.
> - **The Vault custodian.** A `Server` sign-CSR under a `vault_pki` CA is
>   refused by design (the S-7 block above). The console does not try to
>   predict it — `CaCertificateOption` does not even carry `key_custody` — it
>   says so beside the list and shows the server's message, quoted from
>   `CertService::sign_csr` in the test.
> - **One sentence was false since S-7 and is corrected**: the CSR dialog's hint
>   said the issued certificate carries no `keyUsage` or `extendedKeyUsage`.
>   Every leaf now carries the profile.
> - **Tests.** `services/certificates.test.ts` (new, 14): the mapping, the
>   three shape refusals, six "does not judge" cases, both endpoints' bodies and
>   the Device twin. `CertificatesPage.test.tsx` (+11): the type offered in both
>   dialogs with the list only for `Server`, a mixed DNS/IP body in order, the
>   blank-row and no-row refusals on both paths, fenced names sent as typed with
>   the `400` verbatim, the Vault refusal verbatim, both I4 twins and a reset on
>   reopen. `e2e/certificates.spec.ts` gains a live-backend test per dialog that
>   waits for the page rather than probing it once — the file's two older
>   dialog tests use a one-shot `isVisible()` and look for labels the page does
>   not have (`Common Name *`, `Key Type`), so they can pass only through their
>   `else` branch; they are left as they are and listed in §13.
> - **Docs.** `docs/pki/README.md` did **not** carry a "the console does not
>   offer this yet" sentence, as the brief expected: the guide said nothing
>   about the console for `Server` at all. It gains an "In the admin console"
>   paragraph instead.
> - **Records: none, verified.** T-288's mitigation is entirely server-side
>   (`check_leaf_names` runs before the CA lookup on both leaf paths) and
>   nothing in Axiam.json or either STRIDE document says anything about the
>   console for `Server` certificates. The form adds no decision the server
>   does not make again.
>
> **Commit 2 — the settings card.**
>
> - **Shipped.** One module, `pages/settings/serverNamesPolicy.tsx`
>   (`ServerNamesFields`, `ServerNamesSummary`), mounted where the list is
>   written: the organization Settings tab (baseline, `PUT
>   /organizations/{id}/settings`), the tenant's own Settings page (`PUT
>   /api/v1/settings`) and the tenant detail page's Security Overrides panel
>   (`PUT /tenants/{id}/settings`). All three say the same four things: the
>   three entry forms, that `.x` means strictly below and not the apex, that
>   empty refuses every `Server` request, and who may widen. Rows, not a
>   textarea: the other settings lists re-parse a textarea on every keystroke,
>   which drops a trailing newline and makes a second line hard to start.
> - **Read-back, not computed.** The tenant pages render
>   `certificate.server_cert_allowed_names` from `GET /api/v1/settings` — the
>   intersection the server computes on every read — and a test changes the
>   list between load and save to prove the page shows the server's answer, not
>   the body it sent. The organization tab shows the stored baseline under its
>   editor for the same reason. No coverage or intersection logic exists in the
>   console; `cleanAllowedNames` trims and drops blank rows and passes a
>   malformed CIDR, a wildcard entry, a trailing dot or a URL through to the
>   server's `400`.
> - **What the plan did not anticipate: three silent-loss paths on `main`
>   since #495,** found by reading the three handlers rather than the form.
>   1. `flattenOrgSettings` omitted the field, the organization `PUT` replaces
>      the whole row, and `SetOrgSettings` defaults an absent list to `[]` —
>      so saving any organization setting emptied the baseline, and
>      `reconcile_tenant_overrides` narrowed every tenant to nothing. Fails
>      closed, but silently undoes an administrator's decision; it is the
>      OPAQUE and OIDC round-trip bugs of earlier waves, for a third block.
>   2. `PUT /api/v1/settings` stores `diff_against_org(effective)`
>      (`repository/settings.rs`, `store_effective_tenant_settings`). With the
>      field absent the effective list is the organization's, the diff is
>      `None`, and a tenant's narrowing was dropped — the tenant went back to
>      the wider organization list. The page now always sends the effective
>      list it loaded; the diff makes that a no-op when nothing was edited,
>      which the "no allow-list" I4 twin states (the body carries the `[]` the
>      server already stores).
>   3. `PUT /tenants/{id}/settings` replaces the override whole, so the panel
>      discarded a narrowing on a save of any other group. The panel gains its
>      own `serverNames` group, re-checked from a stored override, rather than
>      riding the "certificate validity" group, because absent ("follow the
>      organization") and empty ("issue none") are different values.
>   None of the three could widen beyond the organization's list, so T-288
>   holds as written; they are recorded under **Fixed** in the CHANGELOG
>   rather than as a threat.
> - **Tests.** `settings.test.ts` (+5: read-back fallback, clean, "judges
>   nothing else", empty), `services.test.ts` (+1 and one assertion: the
>   flatten carries the list; absent reads as `[]`), `SettingsPage.test.tsx`
>   (+8), `OrganizationDetailPage.component.test.tsx` (+5),
>   `SecurityOverridePanel.test.tsx` (+7): each regression above pinned on its
>   own page, the widening `400` quoted from `validate_tenant_override`, the
>   explicit-empty override kept distinct from inheriting, and the I4 twins
>   (no key sent while the panel group is unchecked; `[]` round-tripped where
>   nothing is listed). `e2e/settings.spec.ts` gains the empty-by-default card
>   and a live widening refused verbatim, which changes nothing server-side.
> - **Docs.** `docs/pki/README.md`'s console paragraph gains the three places;
>   the website's Server-certificate block gains one sentence
>   (`website/src/docs/operate.ts`; website lint, type-check and build run).
> - **Records: none, verified**, as for commit 1: the tighten-only interlock,
>   the org-side validation and the intersection are all in
>   `axiam_core::models::settings`, and the console only carries values to
>   them.


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

> **EXECUTED — 2026-09-23, PR E, one commit** (branch `feat/grpc-client-auth`, cut
> from `588172a`).
>
> **Shipped.** `AXIAM__GRPC_TLS_CLIENT_AUTH` (`off` default | `optional` |
> `required`) and `AXIAM__GRPC_TLS_CLIENT_CA_PATH`, parsed by a pure
> `axiam_server::tls::resolve_grpc_tls` over a variable reader, so every
> combination is tested from a map and none by mutating the environment.
> `build_grpc_rustls_server_config_with_client_auth` is the builder;
> `build_grpc_rustls_server_config` keeps its name and signature and is exactly
> the `off` call, so the T-234 handshake has one spelling. `grpc_tls_from_env`
> panics on every refusal, as it already did for an unreadable pair. The
> deferral comment (`tls.rs:1269-1277` on `588172a`, "What it deliberately does
> not share") is **rewritten**, not appended to: it now describes the control
> and why it is a second verifier instance.
>
> **(a) One mechanism, two instances, one reload.** The REST listener's
> `LIVE_VERIFIER` is a set-once slot holding one policy. The gRPC listener gets
> its **own** `ReloadableClientCertVerifier` for two reasons. The policy is fixed
> per verifier, and the two listeners may differ (REST `optional` for browsers,
> gRPC `required` for the mesh). And either listener may be the only one with
> TLS on. Every verifying gRPC config registers in `GRPC_VERIFIERS` (weak
> references, pruned on reload). `reload_trust_anchors` reloads REST as before
> and then every gRPC listener. The gRPC side **re-reads its own
> `CLIENT_CA_PATH`** rather than taking the PEM it was handed: a listener must
> never trust a set its next boot would not read, which is the write-then-swap
> rule `mtls_anchors` already follows. Pointed at the REST bundle (the
> documented topology), it picks up exactly what `TrustAnchorReload` just wrote.
> `a_reloaded_anchor_is_honoured_on_the_grpc_listener` drives the whole path:
> flag CA B in the database, `TrustAnchorReload::reload`, bundle rewritten,
> gRPC verifier re-reads it. A certificate from B is then admitted on a new
> connection and satisfies a bound token, where it was refused before.
>
> **(b) Config validation.** Seven cases refuse to boot: an unknown mode;
> `optional_self_signed` (named in its own message); `optional`/`required`
> without a bundle; a bundle while the mode is `off`; an empty or unreadable
> bundle; and **either client-auth variable set on a plaintext listener**
> (neither certificate variable, or only one). The last was the open question.
> It is a refusal because the operator's intent is unambiguous, and cleartext
> on a port believed to be mutually authenticated is the worst reading
> available. Half a certificate pair *alone* stays the silent plaintext it
> always was (I1). An explicit `CLIENT_AUTH=off` is accepted everywhere, and an
> empty value counts as unset, so a Compose `${VAR:-}` does not trip anything.
>
> **(c) The payoff of S-3, confirmed rather than assumed.** No capture code was
> needed in `tls_incoming`. tonic 0.14.6's `Connected for TlsStream<T>`
> (`transport/server/conn.rs:106`) fills `TlsConnectInfo::certs` from
> `peer_certificates()`, and `Request::peer_certs()` (`request.rs:260`) reads
> that extension. Both were read in the pinned source, and the path is asserted
> through the real `start_grpc_server`. The probe is `TokenService/IntrospectToken`
> on the caller's own token: the interceptor alone decides between
> `Unauthenticated` and an answer, and the answer echoes `cnf.x5t#S256`. Tests:
> `a_bound_token_with_its_certificate_is_accepted` (both verifying modes, with
> the unbound-token twin), and
> `a_bound_token_presented_with_a_different_certificate_is_refused` (another
> device's valid certificate from the same anchor, so only the binding can
> refuse; plus no certificate, which is `Unauthenticated` under `optional` and a
> handshake refusal under `required`). The module docs of `tls_incoming` now say
> this, beside the peer-address paragraph that made the same argument for the
> rate limiter.
>
> **(d) I1.** `off` calls `with_no_client_auth()`. That is deliberately not
> REST's `off`, which installs an empty reloadable verifier that flagging a CA
> can later arm; gRPC's `off` must stay off. `off_is_byte_for_byte_todays_handshake`
> reaches `off` through `resolve_grpc_tls` with only the pair set. It probes
> four client shapes (anonymous, certificate-holding, TLS 1.2-only,
> `http/1.1`-only ALPN) against both the production `off` config and the
> pre-S-8 configuration reconstructed from the code it replaced. For each it
> compares server acceptance, whether a `CertificateRequest` was sent (a client
> resolver records whether rustls asked it), the peer certificates the server
> holds, the ALPN and the version. It then asserts one layer up: a client
> holding a certificate is not asked for it, and its bound token is refused over
> the real listener.
>
> **Tests.** `crates/axiam-server/tests/grpc_client_auth.rs`, six:
> `off_is_byte_for_byte_todays_handshake`,
> `required_refuses_a_handshake_without_a_client_certificate` (plus a foreign
> CA, and the I4 twin: a chained certificate admitted and held),
> `optional_accepts_both_and_exposes_the_certificate_when_present`, the two
> bound-token tests, and `a_reloaded_anchor_is_honoured_on_the_grpc_listener`.
> Ten unit tests in `tls.rs`: the seven refusals and their twins over
> `resolve_grpc_tls`, the build-time empty-bundle refusal,
> `a_reload_that_empties_the_grpc_bundle_keeps_the_previous_anchors`, and
> `only_a_listener_on_the_written_bundle_reports_the_reload_as_applied`.
> `axiam-server` lib 120, `grpc_client_auth` 6 (five repeat runs),
> `mtls_anchor_reload` 6, `healthcheck` 9, `grpc_tls_crypto_provider` 1.
> **Three deliberate mutations** each turned the right tests red: the verifying
> modes falling back to `with_no_client_auth()` (5 of 6 red, `off` correctly
> green), the reload skipping gRPC (the reload test red), and `off` sending a
> `CertificateRequest` (the I1 red on the first shape).
>
> **What the plan did not anticipate.**
>
> 1. **A reload's "applied" needed defining, and the first definition was
>    wrong.** The admin handler reports `restart_required` when the reload
>    returns `None`. A gRPC-only deployment must therefore return a count, or
>    the operator is told to restart when nothing needs it. I first returned
>    "the count of the last gRPC listener reloaded". The combined test run
>    caught that: with several listeners in one process the answer depended on
>    iteration order. The honest definition is the one shipped:
>    `reload_trust_anchors(pem, written_to)` counts a gRPC listener as applied
>    only if its bundle **is** the file just written. A listener on a curated
>    bundle of its own is still reloaded, but the flagged set did not reach it.
>    The one caller, `TrustAnchorReload`, passes its bundle path.
> 2. **An empty bundle on reload keeps the old anchors, unlike REST.** REST's
>    `replace` of an empty set means "stop asking", correct when the last CA is
>    unflagged. Under gRPC `required` that is a listener verifying nobody, and
>    the boot path refuses an empty bundle, so a reload must not reach that state
>    either. Unreadable or empty: logged, previous anchors kept.
> 3. **`docs/deployment/README.md` had no gRPC TLS section.** The plan names one;
>    the only gRPC TLS documentation was the website's two configuration rows and
>    the Pi runbook §14. A subsection now sits in "TLS termination". The gate also
>    needed the two rows on `website/src/docs/configuration.ts`, and
>    `docs/pki/README.md`'s "Over gRPC" paragraph, which said a bound token is
>    always refused there, now describes the default instead of the only posture.
> 4. **The threat entry is new, not amended.** No entry in either STRIDE document
>    or `Axiam.json` described the listener's missing client authentication (the
>    gRPC element carries only T-12, cross-tenant introspection). Per §9 it is
>    **T-286**, on `gRPC API (Tonic)` in the system diagram, Spoofing, High,
>    Mitigated. DF-005's point, that `ReactorAdminService` sits on this listener
>    and revocation is skipped by default, is in the threat text. **T-234**
>    gains the closed follow-up; **T-283**'s gRPC paragraph is amended, since
>    it said "`with_no_client_auth()` today, which S-8 changes". `threatTop`
>    285 → 286.
> 5. **`threat-model-stride.md`'s own header table was stale** (280 threats,
>    258 / 13) against its §7 (285). It now reads 286 / 273 / 13, matching §7.
>    That is the document agreeing with itself, not the Axiam.json
>    reconciliation, which remains the maintainer's: `gen-threat-model.mjs`
>    reports *"threatModel.ts: 9 diagrams, 277 threats (264 mitigated, 13
>    open)"*, still nine short of the documents; generated files reverted.
> 6. **Test dependencies.** `axiam-server` gains dev-dependencies on
>    `axiam-api-grpc` with `client` (the generated stubs), `tonic` and
>    `tokio-rustls`. `check-crate-layering.py` is content: the production edge
>    already existed.
> 7. **Line drift.** Checked against `588172a`. `tls.rs:810`, `:1171` (the
>    REST load, inside the plan's `:1155-1181`), `:1233-1238`, `:1289`,
>    `:1345`, `:1361` (`with_no_client_auth()`, inside the plan's `:1355-1364`)
>    and `tls_incoming.rs:119` all matched. The deferral heading is at `:1269`,
>    not `:1270`, and `strict_revocation` at `config.rs:106-107`, not `:105-106`.
>    The same builder lines on `2fc0193` are identical, so the plan's numbers
>    were the body, not the signature.
>
> **Records.** T-286 (Axiam.json, both STRIDE documents, counts: 286 threats,
> 273 mitigated / 13 open; Spoofing 69, High 133, system diagram 32). T-234 and
> T-283 amended in all three. Roadmap T22.12. CHANGELOG under **Added**. No
> OpenAPI or management-registry change: no REST DTO or response line moved.
> The FAPI 2.0 and Basic OP conformance results of 2026-09-11 stand (§7.2); no
> run is claimed here, since nothing under `/oauth2/*` changed.

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

> **EXECUTED — 2026-09-23, PR F, one commit** (branch `feat/m2m-management`, cut
> from `94a0865`, the merge of #493).
>
> **Shipped.** The eight D-5 families take `AuthenticatedPrincipal`: **66
> handlers** in `handlers/{resources,scopes,permissions,roles,groups,
> service_accounts,certificates,webhooks}.rs`, which serve exactly the **66 of
> the 146 routes** in `ROUTE_PERMISSION_MAP` whose permission is in those
> families. §3 says "~100 handler signatures" and §4 says "~70". Both counted
> something wider: ~100 is every `.check(&user, …)` site, which the plan's own
> `RequirePermission` doc comment also calls "~100". D-5 is
> `permissions::M2M_MANAGEMENT_FAMILIES` / `HUMAN_ONLY_FAMILIES` (8 + 18 = the
> 26 families of `PERMISSION_REGISTRY`). The OpenAPI document gains a
> `service_account` security scheme, listed as an alternative to `bearer` on
> those 66 operations and on the two `/authz/check` routes. `bearer` gains a
> description. The audit middleware reads the actor type from `sub_kind`.
> `grant.pre_assign` payloads gain `actor_type`. The operator note at
> `axiam-auth/src/token.rs:1240` (the plan's `~1230`) now lists what a service
> account can call.
>
> **Tests.** `crates/axiam-api-rest/tests/m2m_management_test.rs`, 14:
> - the registry-placement test;
> - the route-map sweep, both directions, with a no-role and a `super-admin`
>   account over all 146 routes;
> - the OpenAPI walk over every other non-public `/api/v1` operation
>   (self-service included);
> - spec ↔ code agreement;
> - per family: viewer → 200, no role → 403 `authorization_denied` naming the
>   action, and the same pair for users (the I4 twin);
> - a provisioning run (role, group, permission, service account, assignment);
> - default-deny;
> - the differential I1;
> - the exchanged-token refusal;
> - the sender constraint;
> - tenant/organization scope;
> - CA scope;
> - CSRF;
> - audit end to end.
>
> Four more in `crates/axiam-audit/tests/service_and_middleware.rs`.
>
> **Six deliberate mutations**, each red in the test meant to catch it:
> - one handler back on `AuthenticatedUser` → the sweep;
> - the `sub_kind` gate removed → the exchanged-token test, which then read
>   `/roles` as the user with no session behind it;
> - the machine check removed from `is_organization_principal` → the CA test,
>   which then issued under the organization root;
> - the old `jti`-only session read restored → the differential test on the
>   `sid` case;
> - the tenant-switch resolution removed from the machine branch (the earlier
>   variant of (d) below) → the header test;
> - `actor_type_of` forced to `User` → both audit tests.
>
> **What the plan did not anticipate.**
>
> 1. **`check_subject` would have broken the I1.** The plan says to switch "from
>    `RequirePermission::check` to `check_subject`". `check_subject` hard-codes
>    `SubjectScope::Tenant`, so an organization administrator acting on a tenant
>    through `X-Axiam-Tenant` would have had their organization grants
>    evaluated as tenant grants on every converted route. `check` now takes any
>    `Caller`, a three-method trait both extractors implement. The ~100
>    unconverted call sites did not change.
> 2. **`AuthenticatedPrincipal`'s user branch was a copy, and the copy
>    differed.** It read the session id from `jti`. `AuthenticatedUser` reads
>    `sid` first, so an OAuth2-issued user token (random `jti`, session in `sid`)
>    passed every unconverted route and would have been refused as "session
>    revoked or expired" on every converted one. That was already true of
>    `/authz/check`. The user branch now *is* `AuthenticatedUser`'s code
>    (`user_from_validated`, the tenant-path binding, `RequestScopeHandles::apply`),
>    converted afterwards. `a_user_token_is_answered_identically_by_both_extractors`
>    compares both extractors over eight token shapes. The
>    absent-`aud` back-compat case is not among them: the public token builder
>    cannot omit `aud`. It is `user_from_validated` on both sides by
>    construction.
> 3. **An exchanged user token was accepted as a machine.** RFC 8693 exchange
>    may target `axiam:m2m` for any subject (`token_exchange.rs:342`) and keeps
>    `sub_kind = user`. The machine branch skips the session check, so such a
>    token would have acted with the *user's* roles and no session behind it,
>    audited as a service account. The machine branch now requires
>    `sub_kind = service_account` (401 otherwise), on `/authz/check` too. That
>    is the one narrowing of existing behaviour in this PR, and it is in the
>    CHANGELOG. The `sub_kind` doc comment said "informational only" and now
>    says what it decides.
> 4. **The T21.6 tenant-path binding was missing from `AuthenticatedPrincipal`.**
>    It is inert today, since no management route is mounted under `/t/`, but a
>    converted route would have silently lost it the day one is. Both branches
>    apply it.
> 5. **(d) was decided twice.** The first version refused `X-Axiam-Tenant` for
>    every machine. Reading the website's service-account page reversed that:
>    an **organization-level service account** is a documented design ("a
>    deployment-wide automation"), `tenant_scope` on service-account assignments
>    exists for it, and before this PR `/authz/check` honoured the header for
>    one. The shipped rule is **the user's rule, through one function**:
>    `act_on_requested_tenant` is now called by both kinds, and every refusal is
>    compared body for body with a user's in the same position. The
>    **exception is the organization CA**: `is_organization_principal` answers
>    `false` for a machine wherever it lives, so a service account issues under
>    the signing CA of the tenant it acts on, or not at all. S-1's gate stays
>    human-only, which is D-5's line for trust-posture acts.
> 6. **The audit middleware recorded every authenticated request as `User`.**
>    The plan says the audit event "carries the principal kind". It did not, for
>    any route: `extract_or_cache_user_info` hard-coded `ActorType::User`. The
>    type now comes from the signed `sub_kind`, which also keeps an exchanged
>    user token recorded as a user. An OAuth2 client's `sub` is not a UUID, so
>    it stays `System` as before.
> 7. **Self-service is not in `ROUTE_PERMISSION_MAP`**, so a sweep over the map
>    alone cannot show `/auth/me` or password change still refusing a machine.
>    The second sweep walks the OpenAPI document instead, and
>    `route_openapi_parity_test` already holds the document to the route table.
>    D-5's "`/users/me`" is `/api/v1/auth/me`.
> 8. **The sweep cannot reach RBAC on routes with a body.** With no body, the
>    `Json` extractor answers 400 before the handler runs. So the sweep asserts
>    "never the audience refusal, never a 2xx" on every admitted route, and
>    403 `authorization_denied` naming the route's own permission on all 41
>    admitted GET/DELETE routes. The per-family and provisioning tests cover the
>    writes with real bodies.
> 9. **(c) confirmed by reading.** `extract_principal` reaches
>    `enforce_sender_constraint` on both paths: `cached_identity` (the
>    audit-middleware cache) and `parse_validated_claims` →
>    `validate_presented_token`. The positive half is still unreachable from
>    `TestRequest` (S-3 note 4), so only the refusal is pinned at the wire, on
>    `GET /roles` with a `super-admin` device token. Its I4 twin is the same
>    account's unbound token, 200.
> 10. **(e) CSRF.** Unchanged, and audience-agnostic by construction.
>     `is_bearer_only` never looks at the token. A bearer-only service-account
>     write is exempt (201); the same write with an `axiam_access` cookie beside
>     the header is refused by CSRF (403 "CSRF validation failed", while the
>     account holds `admin`).
> 11. **Disk, and what the full suite showed.** The whole `axiam-api-rest`
>     suite exceeds this sandbox's write allowance in one build. It was run one
>     target at a time with `--no-default-features`, deleting each executable
>     after its run. Result: 86 of 87 targets green, 1,344 tests. The one red
>     target was `federation_test`: 15 SAML tests answered 404. That binary is
>     not feature-gated while the SAML routes are (`server.rs:546`, `:1416`),
>     so with `saml` off they do not exist. It is unrelated to this diff, and
>     CI runs that binary only with default features. Rerun here with default
>     features once libxml2 was installed: 78 of 78. The binaries this commit
>     touched, and their closest neighbours, were run three times each with
>     default features, all green every time: `m2m_management_test`,
>     `certificate_test`, `rbac_test`, `role_assignment_scope_test`, the
>     crate's lib tests and `axiam-audit`'s `service_and_middleware`.
>
> **Records.** **T-287** on `REST API (Actix-Web)` in the system diagram,
> Elevation of privilege, High, Mitigated. It is recorded in Axiam.json and in
> both STRIDE documents (287 threats, 274 / 13; Elevation of privilege 58, High
> 134, system diagram 33). `gen-threat-model.mjs`: *"threatModel.ts: 9
> diagrams, 278 threats (265 mitigated, 13 open)"*, still nine behind the
> documents, and the generated files were reverted. Roadmap T22.13. CHANGELOG
> under **Changed**. Docs: `docs/api/README.md` gains "Authentication — who may
> call which route", and the website's audience section gains a paragraph.
> OpenAPI and the management registry are regenerated. No `/oauth2/*` route
> changed, so the FAPI 2.0 and Basic OP results of 2026-09-11 stand (§7.2).

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

> **EXECUTED — S-10b, 2026-09-23, PR G2, commits 3 and 4 of 5** (the console half of
> item 11 above; roadmap **T22.11b** — numbered after the task it completes,
> since this roadmap's T22.10 is the console resolver, S-11).
>
> **Commit 3 — the flag in the dialogs and the listings.**
>
> - **Shipped.** `services/roles.ts` carries `inherit?` on every assignment
>   row and a fifth `inherit` argument on the three assign calls, sent only as
>   `false` (`inheritField`), so an inheritable assignment's body is
>   byte-for-byte today's. `assignmentInherits` reads absent as `true`, as the
>   repository does; `canChangeInherit` is the one predicate for "a resource,
>   and not a global role". `InheritToggle` (in `AssignmentScope.tsx`) is
>   rendered by all five assign surfaces — the shared `AssignRoleDialog` (user
>   and group pages) and the role page's user, group and service-account
>   dialogs — only when that predicate holds for the chosen resource and role,
>   and a hidden unchecked box falls back to `true` on submit, so switching to
>   a global role or clearing the resource can never send the 400. The service
>   account dialog is included although the brief names users and groups: it is
>   the same rule on the same page, and the server takes the flag on all three
>   routes.
> - **Listings.** `AssignmentScopeBadge` gains `inherit`: a *This resource
>   only* chip, and a resource tooltip that no longer says "and its
>   descendants" on a row that has none. Shown on the role page's three tabs
>   and the group page. The user page has no listing (it points to the Roles
>   page), so there is nothing there to badge.
> - **Toggling is unassign-then-assign** (`roleService.setAssignmentInherit`,
>   `components/AssignmentInheritChange.tsx`), never a second assign — that is
>   a 409 by design. A refused unassign changes nothing and says so. A refused
>   re-assign assigns the **old** assignment again (same resource, same
>   `tenant_scope`, old flag) and throws `AssignmentToggleError { restored:
>   true }`; if that restore fails too, `restored: false` and a message that
>   begins "The user no longer holds this role at this resource". The dialog
>   stays open with the outcome, and the listing is re-read after every
>   attempt, because a half-done change is still a change. Between the two
>   calls the subject holds nothing, which the confirmation states before the
>   first click, together with the direction: `false` on a deny re-opens the
>   subtree.
> - **One wording collision fixed before commit.** The row action for an
>   inheritable assignment was first labelled *This resource only* — the badge
>   text for the opposite state. The I4 test caught it; the action now reads
>   *Stop here*, the confirmation *Apply here only*.
> - **Tests.** `services/roles.test.ts` (new, 15): the field on all three
>   routes, the I4 twins (omitted and `true` send no key), the server's
>   no-resource refusal passed through, the two predicates, and every branch of
>   the change — order of the two calls, the scopes and old flag carried into
>   the restore, restored, not restored, refused unassign.
>   `AssignRoleDialog.test.tsx` (new, 8), `AssignmentScope.test.tsx` (+6),
>   `RoleDetailPage.test.tsx` (+12), `GroupDetailPage.test.tsx` (+4). Every
>   refusal is quoted from `validate_inherit`. `e2e/matrix/assignment-inherit.spec.ts`
>   (new, 3) is **read-only** against the live fixture — a scoped assignment
>   made without the field reads as inheritable, the dialog offers the flag
>   only after a resource is chosen, a global role's rows offer nothing —
>   because `resource-hierarchy.spec.ts` depends on mx-editor's assignment
>   cascading, and toggling it there would make that file's answers depend on
>   run order.
> - **Records: T-285 amended, no new threat — verified.** Its residual said the
>   console does not offer the flag; Axiam.json and the STRIDE detail block now
>   say what it does. Nothing new is decided client-side: both 400s are the
>   server's (`validate_inherit`), the change is the two calls the S-10 block
>   already verified invalidate, and the console only chooses not to offer what
>   would be refused. `gen-threat-model.mjs`: *"threatModel.ts: 9 diagrams, 279
>   threats (266 mitigated, 13 open)"* — unchanged; generated files reverted.
>
> **Commit 4 — asking before a role is made global.**
>
> - **Shipped.** `useMakeRoleGlobalGuard` (hook) and `MakeRoleGlobalConfirm`
>   (dialog), used by both places that edit `is_global`: the role list's and
>   the role page's *Edit Role*. The guard does nothing — no read, no dialog,
>   the same `PUT` — unless the save moves `is_global` from false to true. Then
>   it reads the role's three assignment listings from the server
>   (`roleService.nonInheritableAssignments`) and asks only if one of them is
>   resource-scoped with `inherit: false`, or if the read failed ("could not
>   check" is not "none"). The question names up to three of them with their
>   resources, counts the rest, and says the effect: each will apply
>   everywhere, the descendants it stopped short of included, and a deny among
>   the role's grants would deny everywhere. *Keep it scoped* returns to the
>   form with its values intact (the form is hidden, not closed); *Make global*
>   sends exactly the body it would have sent.
> - **A confirmation, not a refusal**, as the brief and T-285 say: the server
>   accepts the change by design, so the console must not make it impossible —
>   only not silent.
> - **Tests.** `roles.test.ts` (+2: the aggregation across all three kinds,
>   excluding cascading and tenant-wide rows; the none case),
>   `RoleDetailPage.test.tsx` (+5) and `RolesPage.test.tsx` (+3): asked and
>   saved on confirm, *Keep it scoped* saves nothing, the failed-read wording,
>   and the I4 twins — only cascading assignments save at once, an edit that
>   leaves the role scoped makes none of the guard's reads before its `PUT`
>   (counted at the instant the `PUT` is issued), and un-making a role global
>   never asks.
> - **Mutations, all four caught, all reverted.** The guard reading on every
>   save (the no-read twin went red); the guard never asking (four tests red);
>   `setAssignmentInherit` skipping the restore (five red, commit 3's); the
>   dialog offering the flag unconditionally (four red, commit 3's).
> - **Records: T-285 amended again, no new threat — verified.** The residual
>   stands, since the server behaviour is unchanged; its text now says the
>   console confirms first. `gen-threat-model.mjs`: *"threatModel.ts: 9
>   diagrams, 279 threats (266 mitigated, 13 open)"*; generated files reverted.

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

> **EXECUTED — 2026-09-23, PR H, as contract 1.51** (branch `docs/contract-1.50`,
> cut from `1cb1371`, the merge of #496; commit "docs(sdk-contract): contract 1.51 — the
> dogfooding remediation (C-0)", plus a records commit).
>
> **Shipped.** Amendments 1–8 below, each written against the code on `1cb1371` rather
> than against the S-blocks above:
>
> - §1 gains three rows, and a new §1.1.1 specifies `validate_token` /
>   `introspect_token`.
> - §5.2 rule 1 becomes a SHOULD, with a per-language table.
> - §6.1 gains rules 6–10 for `authenticate_device()`.
> - §27.0 lists all five registry exclusions, with `/admin/bootstrap`'s outcome table.
> - §27.5 gains rule 5, and a new §27.6.1 carries the manifest additions.
> - §27.10 gains the per-SDK manifest table.
> - §10.3 gains the pointer to the new operations.
> - A new §27.13 carries the S-4 / S-7 / S-9 / S-10 notes. Every new request field is
>   optional, so existing SDK request types keep working unedited. §27.13 says so, and
>   names the two response-side changes that are *not* free for a decoder.
>
> The Breaking Changes Log gains a 1.51 entry, and the footer names 1.51. The website's
> `contractAnchors.ts` is regenerated, and the reference page's version table gains 1.49,
> 1.50 and 1.51. `openapi.json`, `management-registry.json` and `proto/` are unchanged.
> No server code changed, and no amendment needed a server or OpenAPI change.
>
> **Gates.**
>
> - Every script gate `ci.yml` and `docs-ci.yml` run exits 0: `check-doc-links.sh`, the
>   docs-lint JSON parse, `gen-management-registry.py --check` / `--self-test`,
>   `check-spec-digest.py`, `check-config-key-coverage.py` and the other fourteen with
>   their self-tests. `check-remediation-evidence.py` reports 37 verified and 0 failed.
>   It first failed 5 rows in this sandbox because the clone was shallow and the cited
>   commits were absent, and it failed identically on a clean tree. CI checks out with
>   `fetch-depth: 0`.
> - Website `oxlint`, `tsc -b` and `vite build` exit 0, and all 92 internal `#§…` links
>   in the contract resolve.
> - `check-sdk-artifact-drift.py --local-root ..` exits 1 with **exactly 33** problems:
>   `CONTRACT.md`, `openapi.json` and `management-registry.json` are STALE in each of
>   the eleven repositories. `proto/`, the OPAQUE vectors and the vendored crate are OK.
>   The last two stale files were already stale on `main`, because the SDKs vendor
>   beta16's (`2617eae`). This is the expected red until C-1 … C-11 re-vendor, and it
>   is the only one.
>
> **What the plan did not anticipate.**
>
> 1. **Contract 1.50 was already taken.** `d5a6811` (2026-09-18, the DCR
>    `initial_access_token` made `Sensitive`) published 1.50, and all eleven SDKs vendor
>    exactly that text (sha256 `d877a1a05e9a…`). The plan was written as if the number
>    were free. On the requester's decision, C-0 ships as **1.51**, C-12 becomes
>    **1.52**, and the branch keeps its planned name. §3 and the C-0/C-12 headings below
>    are left as written, and this block and §13 carry the correction.
> 2. **§10.3 names RPCs, not SDK operations.** Item 1's "the operation names §10.3
>    already uses" is loose: §10.3 says `TokenService.ValidateToken` /
>    `IntrospectToken`. The snake-case names are introduced by §1 and not inherited, and
>    §1.1.1 carries seven rules for them. Two of those rules come from the code. First,
>    the server reports `token_type: "Bearer"` for a certificate-bound token, so
>    boundness is decided from `cnf` alone. Second, a token from another tenant is
>    `valid: false`, not an error.
> 3. **The acting tenant is REST-only, and a malformed value fails silently.** The gRPC
>    interceptor reads only `authorization`, and the tenant always comes from the token,
>    so the contract says REST-only rather than inventing a metadata key (C-1's check,
>    answered here). The REST extractor parses `X-Axiam-Tenant` as a UUID and **drops** a
>    value that does not parse, so the request acts on the caller's own tenant and
>    succeeds. That is T-210's failure mode by a second path, so the helper must refuse a
>    non-UUID client-side.
> 4. **"Reachable only when the flag is true" cannot be applied to every caller.** A
>    construction-time option precedes the login that reveals `organization_level`, and a
>    service account never receives a login result at all. An organization-level service
>    account is a supported design (S-9 note 5). So the rule is split: an SDK gates on
>    the flag and on `reachable_tenant_ids` when it holds a login result, and otherwise
>    the server's `403` is the answer.
> 5. **§6.1's intro contradicted S-1.** It said device certificates are "signed by the
>    tenant's organization CA". Since T22.1 a tenant principal issues only under its
>    tenant signing CA, and since T22.13 a service account always does. Corrected.
> 6. **§27.0 listed two of the registry's five exclusions.** `GET /health/jobs` and
>    `POST /users/me/resend-verification` were missing as well as `/admin/bootstrap`, and
>    all three are added from the registry's own reasons. Bootstrap's outcome table was
>    read from the handler: 201 / 400 / 403 / 409, a public route with no `401`, and the
>    gate checked before the fields. Found, not fixed: **`/admin/bootstrap` has no rate
>    limiter** (§13 row 15).
> 7. **Every figure in §27 was stale.** The prose said 147 operations, the §27.1 table
>    summed to 148, and the registry holds 162. Only three operations are
>    unauthenticated, not "the four in `platform`" plus one. It is 18 namespaces with a
>    `list` and 17 with a `get`, not 20 and 14; 21 paginated operations, not 20; 19
>    bare-array reads, not 13; and 34 routes with a `{org_id}`/`{tenant_id}` segment,
>    not 31. Re-rendered from the registry, with the requester's agreement, since §27.0
>    says a table that disagrees with the registry is the one that is wrong.
> 8. **The manifest additions needed four rules the plan did not state**, each taken from
>    the server.
>    - `has_role` is `UNIQUE(in, out)`, so one subject bound to one role twice is
>      unsatisfiable and is rejected client-side (D-3).
>    - Assignments have no update endpoint, so a changed binding is unassign-then-assign
>      with a restore on failure: the console's T22.11b behaviour.
>    - That re-assignment must carry `tenant_scope` across, or it would silently widen
>      an organization-level account.
>    - Service-account names are **not unique**: only `client_id` is indexed. So a
>      stated name matching two accounts fails `plan` rather than picking one.
> 9. **§27.5: what `apply` returns for a new service account's secret.** The rule is the
>    `create` return, once, `Sensitive`, on that action's outcome, **even when a later
>    action fails**; `apply` never rotates to reconcile. The reason is the imperative
>    contract. `POST /service-accounts` is the only moment the plaintext exists: `get`
>    and `list` return `ServiceAccountResponse` with no secret field, the server keeps a
>    hash, and `rotate_secret` invalidates the old secret rather than revealing it. So the
>    manifest can only return it where `create` does, and dropping it would create
>    accounts nobody can use, which the next `apply` reports as `NoChange`. The same
>    argument explains why service accounts are in the manifest and certificates are
>    not: an account's identity is separate from its secret, whereas a certificate *is*
>    its key.
> 10. **S-7 has a response-side consequence.** `"Server"` appears in `certificates.list`
>     and `get`, so an SDK with a closed `CertificateType` enum fails the whole list on
>     one server certificate: the `TenantKind` lesson of §27.11 rule 1, stated again.
>     And `SetOrgSettings.server_cert_allowed_names` defaults to `[]` under `replace`
>     semantics, so a `set_org` that omits it empties every tenant's list: the S-7b
>     console bug, which an SDK's read-modify-write form must not reproduce.
> 11. **S-9 is by permission, not by registry namespace.** 66 registry operations accept
>     a service-account token, `users.list_roles` (`roles:get`) among them, and the
>     registry does not record which. §27.13 points at `openapi.json`'s per-operation
>     `security` as the authority and forbids client-side gating on token kind.
> 12. **The SDK manifests are further behind than §6 says**, read from all eleven
>     repositories' code.
>     - Nobody has `service_accounts`, and nobody binds a role at a resource.
>     - Only PHP has `metadata`.
>     - In the flat tier (PHP, Swift, C, C++), none of the four sends a resource's
>       `parent_id` on create, so trees are created flat.
>     - Swift, C and C++ default `resource_type` to `"folder"`.
>     - **PHP stores role grants and group role keys and never reconciles them**, while
>       its docblock says it does.
>
>     All of this is in §27.10 as fact, with the three defects assigned to C-6, C-9,
>     C-10 and C-11. Also: `TokenService` stubs are generated in five repositories, not
>     nine, and are wrapped in none. Go's sit under `internal/`, and Python and PHP
>     generate none.
> 13. **The website's contract version had been stuck at 1.48.** `CONTRACT_VERSION` is
>     derived from the footer, which 1.49 and 1.50 never updated. The footer now names
>     all three versions, and the reference page's version table (last touched at 1.48)
>     gains its three rows.
>
> **Records.**
>
> - **Threat model: no new entry, one amendment — verified.** The entries on the
>   contract store and on the SDK processes were read: T-139 … T-149, T-167, T-175,
>   T-183 … T-186, T-199, T-209 … T-211, T-235, T-265 and T-266.
>   - **T-210** claimed that "the eleven contract-1.35 SDK fan-out PRs already implement
>     the real header". A search of all eleven repositories finds `X-Axiam-Tenant` only
>     in doc comments, so the sentence is corrected in `Axiam.json` and
>     `threat-model-stride.md`. It gains the malformed-UUID path and its 1.51 mitigation.
>     Severity, status and counts are unchanged.
>   - The one-time `client_secret` on a manifest outcome sits under T-139's `Sensitive`
>     mitigation, unchanged.
>   - The certificate-bound device token is T-283's, and §6.1 rule 9 is its SDK-side
>     statement.
>   - `gen-threat-model.mjs` reports *"threatModel.ts: 9 diagrams, 279 threats (266
>     mitigated, 13 open)"*, unchanged. The generated files were reverted.
> - Roadmap **T22.15**.
> - CHANGELOG under **Documentation**.
> - §13 row 1 updated, and a "Found during PR H" table added.
> - No `/oauth2/*` route changed, so the FAPI 2.0 and Basic OP results of 2026-09-11
>   stand (§7.2). No run is claimed.

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

> **EXECUTED — 2026-09-24, PR I₁, against contract 1.51**
> ([ilpanich/axiam-rust-sdk#115](https://github.com/ilpanich/axiam-rust-sdk/pull/115),
> branch `feat/contract-1.51`, cut from `7d27160`). §13 row 1 allowed either branch
> name, and this one names the contract actually implemented. **Merged** as `8e9eb90`
> on 2026-09-24, with CI green on its head `01a1ef1`. Nothing is tagged or published.
>
> **Shipped.** One commit per piece, in this order:
>
> - **Re-vendor** from `56fbe44`, the merge of #497. `CONTRACT.md` (sha256
>   `0ac7fd75f83c…`), `openapi.json` and `management-registry.json` byte-match that
>   commit, and `proto/` was already identical. The §27 surface is regenerated at 162
>   operations. `CertificateType` already decoded openly, so §27.13 S-7 rule 2 needed a
>   test and no change.
> - **Acting tenant, §5.2 rule 1.** The builder form is `with_acting_tenant(Uuid)`. The
>   on-client form is `acting_tenant(Uuid)`, which returns a new handle over the same
>   session, plus `clear_acting_tenant()`. The value is scoped to the handle rather than
>   shared, so two tasks acting on two tenants cannot rewrite each other's header. It is
>   gated on a held login result, and it is REST-only.
> - **`authenticate_device()`, §6.1 rules 6–10**, plus `examples/device_mtls_login.rs`.
>   `examples/device_login.rs` (RFC 8628) is untouched. Rule 7 is met by its client-side
>   branch: `AuthError` with zero wire calls.
> - **`grpc::TokenGrpcClient::{validate_token, introspect_token}`, §1.1.1 and §10.3.**
>   The rule-9 table moves onto `CnfClaim::verify`, so local verification and gRPC
>   validation share one implementation.
> - **`JwksVerifier` and `cnf`, §10.1 rule 9: a real defect, fixed.** `verify()` is the
>   entry point `AxiamUser`, the §11 macros and the §28 guard all reach, and it accepted
>   a certificate-bound or DPoP-bound token as a bearer token. A device token lifted off
>   a device therefore opened every guarded route. `verify()` now refuses a bound token
>   it has no evidence for. `verify_with_proofs` and `middleware::PeerCertificate`
>   (recorded in `on_connect`, never from a header) accept one. The test that pinned the
>   defect is inverted, not relaxed.
> - **Manifest, §27.6.1 and §27.5 rule 5.**
>   - `ResourceSpec.metadata` compares by equality of the whole object.
>   - `RoleBinding` has two shapes. `inherit` reaches the wire only as `false`, and a
>     role bound twice is refused before any request. An update is unassign then
>     assign, with `tenant_scope` carried across and the previous binding restored if
>     the assign fails.
>   - `ServiceAccountSpec` is reconciled by name, and an ambiguous name fails `plan`.
>     The one-time `client_secret` survives a later failure in the report, and nothing
>     is ever rotated.
>
> **Tests.** Every §8 rule 7 test ships, each negative test with its I4 twin. There are
> 49 tests in six new files, plus three added to `local_verification_set_test.rs`, and
> the suite reports 985 passed and 0 failed. Every mutation deliberately introduced
> (fourteen across the six feature commits, each named in its commit message) was
> caught by the test meant to catch it.
>
> **Gates.** Every job of `sdk-ci-rust.yml` passes, on stable and on MSRV 1.88:
>
> - fmt, and clippy `-D warnings`;
> - `cargo doc -D warnings`, the examples, the leak and TLS-lint gates, `--features
>   grpc`, and the macros publish dry-run;
> - the §27.8 drift check;
> - the wasm32 check, `wasm-pack` for all three targets, and the smoke test;
> - `buf` lint, format and breaking;
> - `cargo audit`;
> - coverage at 92.08 % of lines, against a floor of 90.
>
> CI's stable toolchain (1.98.1) then raised `clippy::result_large_err`, which the
> local 1.94 did not, and CodeQL raised six test-only alerts. Both were fixed on the
> branch (`fa132c2`, `c853412`).
>
> **What the plan did not anticipate.**
>
> 1. **The verifier defect was real, and breaking to fix.** The plan's "if the verifier
>    ignores `cnf` today" was the case. A resource server that accepted device tokens
>    through `verify()` now answers `401` until it records `PeerCertificate`. The
>    CHANGELOG lists this under Breaking.
> 2. **The generator had two defects the re-vendor exposed.**
>    - `SubjectAltName` is an externally tagged `oneOf`, and the generator emitted it
>      as an empty struct that serializes as `{}`.
>    - A required `inherit` on the role-side listings would fail the whole listing
>      against a pre-1.51 server.
>
>    Both are fixed in `tools/gen_management.py`. Every other SDK's generator is exposed
>    to the same pair; see C-12 item 3 below.
> 3. **A device token must not ride next to a stale cookie.** The server reads the
>    `axiam_access` cookie before the `Authorization` header. An SDK that adopts the
>    device token while keeping its jar would therefore run as the previous session's
>    principal. Rust sends the token as a bearer credential with an explicit empty
>    `Cookie` header.
> 4. **The service-account manifest cannot rely on unique names.** The server does not
>    enforce them, so reconciling by name must fail `plan` on more than one match
>    rather than pick one.
> 5. **A plain binding over a resource-scoped server assignment is now an `Update`.**
>    Presence used to be all that was compared. §27.6.1 defines the plain shape as "no
>    resource", so this is a behaviour change, recorded in the CHANGELOG.
> 6. **Two pre-existing gaps were found and left alone, both outside C-1's scope.**
>    First, `cargo build --no-default-features --features grpc` fails, because `pub mod
>    management` is not gated on `rest`, and CI never builds that combination. Second,
>    §27.7 lists `#[derive(AxiamSpec)]` for Rust, which has never shipped; the README
>    declines it.
>
> **Declines (§8 rule 5).**
>
> - `webhooks` in the manifest (§7.2).
> - §6.1 rule 7 as a typestate. It would make `AxiamClient` generic in every caller for
>   the sake of one operation, and the rule names the client-side `AuthError` as
>   conforming.
> - `#[derive(AxiamSpec)]`, per item 6.
>
> **For C-12: questions the contract leaves open, as the reference resolved them.**
> The ports will meet each of these, so C-12 checks them across all eleven SDKs, and
> any that need text go into 1.52.
>
> 1. **§10.1 rule 9 at the default entry point.** The contract says a bound token "MUST
>    NOT be accepted as" a bearer token, but it does not say that the SDK's *default*
>    verify call is bound by it when that call has no transport evidence. Rust reads it
>    as bound: the default call refuses. Every SDK whose route guard calls a plain
>    `verify` probably has the defect Rust had, so C-12 checks each one. A 1.52 sentence
>    naming the default entry point would stop the question recurring.
> 2. **The §17 memo key and the acting tenant.** §17 rule 3 keys the memo on
>    `(subject_id, resource_id, action, scope)`, but since 1.51 one session can ask the
>    same question of two tenants. Rust adds the acting tenant to the key. Without it, a
>    memoized answer for tenant A is returned for tenant B within the TTL. Candidate
>    amendment: the key gains the acting tenant.
> 3. **Generated DTOs from the 1.51 spec.** `SubjectAltName`'s externally tagged
>    `oneOf` and the required role-side `inherit` (item 2 above) will trip other
>    generators. C-12 checks that each SDK sends `{"dns": …}` / `{"ip": …}` rather than
>    `{}`, and decodes a listing without `inherit` as `true` (§27.13 S-10 rule 3).
> 4. **Device-token adoption beside a cookie jar (item 3 above).** §6.1 says to adopt
>    the token, but does not say to withhold the jar. Candidate amendment: say so, and
>    say why.
> 5. **Which sessions count as "holding a login result" (§5.2 rule 1).** OPAQUE, SSO,
>    WebAuthn and the MFA setup complete a session without a `LoginUserInfo`. Rust
>    treats each of them as holding none: it sends the header and lets the server's
>    `403` answer. A port that keeps an older login result across such a session would
>    gate on the wrong principal.
> 6. **The global role bound with `inherit: false`.** §27.6.1 says an SDK MAY refuse it.
>    Rust refuses it before any request. C-12 records each SDK's choice, because a
>    mixture is conforming but surprising.
> 7. **An `Update` of a binding is two calls.** Unassign then assign is not atomic.
>    Rust restores the previous binding when the assign fails, and reports
>    `BindingUpdateFailed { error, restore }`. The contract does not say what a failed
>    rebind leaves behind.

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
Start from the seven open questions in C-1's EXECUTED block ("For C-12"): each is a
place where the ports can diverge while each still reads the contract correctly.

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

### 8.1 Fan-out record

One row per SDK, updated as each PR opens, turns green and merges. "Declines" names
every piece the SDK does not ship, as the README and the per-SDK table state it.

| Task | SDK | Repository | Branch | PR | State | Declines |
|---|---|---|---|---|---|---|
| C-1 | Rust (reference) | `ilpanich/axiam-rust-sdk` | `feat/contract-1.51` | [#115](https://github.com/ilpanich/axiam-rust-sdk/pull/115) | merged (`8e9eb90`) | `webhooks` in the manifest; §6.1 rule 7 as a typestate (the client-side branch instead); §27.7 `#[derive(AxiamSpec)]` |
| C-2 | TypeScript | `ilpanich/axiam-typescript-sdk` | `feat/contract-1.51` | [#116](https://github.com/ilpanich/axiam-typescript-sdk/pull/116) | merged (`9102c91`) | `webhooks` in the manifest; §6.1 rule 7 as a typestate (the client-side branch instead) |
| C-3 | Python | `ilpanich/axiam-python-sdk` | `feat/contract-1.51` | [#88](https://github.com/ilpanich/axiam-python-sdk/pull/88) | merged (`231a686`) | `webhooks` in the manifest |
| C-4 | Java | `ilpanich/axiam-java-sdk` | `feat/contract-1.51` | [#102](https://github.com/ilpanich/axiam-java-sdk/pull/102) | merged (`fa6803a`) | `webhooks` in the manifest |
| C-5 | C# | `ilpanich/axiam-csharp-sdk` | `feat/contract-1.51` | [#95](https://github.com/ilpanich/axiam-csharp-sdk/pull/95) | merged (`d1dc37a`) | `webhooks` in the manifest; §6.1 rule 7 as a typestate (the client-side branch instead) |
| C-6 | PHP | `ilpanich/axiam-php-sdk` | `feat/contract-1.51` | [#73](https://github.com/ilpanich/axiam-php-sdk/pull/73) | merged (`ceb7f2c`) | `users`/`scopes` manifest entities (flat tier, §7.2); `webhooks` in the manifest |
| C-7 | Go | `ilpanich/axiam-go-sdk` | `feat/contract-1.51` | [#86](https://github.com/ilpanich/axiam-go-sdk/pull/86) | merged (`9013027`) | `webhooks` in the manifest |
| C-8 | Kotlin | `ilpanich/axiam-kotlin-sdk` | `feat/contract-1.51` | [#68](https://github.com/ilpanich/axiam-kotlin-sdk/pull/68) | merged (`fbf98c5`) | no gRPC transport (so §1.1.1/§10.3 wrappers); Ktor-engine mTLS evidence wiring; `webhooks` in the manifest |
| C-9 | Swift | `ilpanich/axiam-swift-sdk` | | | not started | |
| C-10 | C | `ilpanich/axiam-c-sdk` | `feat/contract-1.51` | [#65](https://github.com/ilpanich/axiam-c-sdk/pull/65) | open | no gRPC (so §1.1.1/§10.3 wrappers); §6.1 rule 7 as a typestate; `users`/`scopes` and role → permission grants in the manifest (flat tier); `webhooks` in the manifest |
| C-11 | C++ | `ilpanich/axiam-cplusplus-sdk` | | | not started | |

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

### 12.1 The port prompt, C-2 … C-11

The ten ports differ from the PRs above: each works in its own SDK repository and
against a reference that already exists. One prompt, parameterised by task. `<TASK>`,
`<SDK>` and `<REPO>` come from §8.1, and `<SCOPE>` from C-2 … C-11's table in §6.
Sonnet 5, effort `high` (§2).

```
You are executing task <TASK> of axiam's
claude_dev/dogfooding-findings-fix-plan.md: the <SDK> port of SDK contract 1.51, in
ilpanich/<REPO>. Scope: <SCOPE>.

Read, before touching anything:
- in axiam: the plan's §6 (C-1, its EXECUTED block, and the C-2 … C-11 table), §8
  (the fan-out rules) and §8.1 (the fan-out record);
- the reference implementation, ilpanich/axiam-rust-sdk#115: its commit messages
  carry the reasoning, and its tests carry the behaviour you must match;
- in <REPO>: CLAUDE.md, if present; the README's conformance section; every CI
  workflow. Record the commands CI runs; they are your gates.

Rules that bind this session:
- Boot SAGE (`sage_inception`) first if the MCP is connected; if not, say so once and
  continue.
- Branch `feat/contract-1.51`, cut from the repository's main. One PR. Signed commits.
- Re-vendor CONTRACT.md, openapi.json, management-registry.json and proto/ from the
  axiam commit C-1 used (`56fbe44`), byte for byte, and regenerate the SDK's §27
  surface with its own generator. Check the generated SubjectAltName and the
  role-side `inherit` against C-1's EXECUTED item 2: C-1's generator got both wrong.
- Implement the reference's behaviour in <SDK>'s own idiom, not Rust's shape
  transliterated. Where the reference made a choice the contract leaves open (C-1
  EXECUTED, "For C-12"), make the same choice, or record a different one with its
  reason.
- Check the SDK's default token-verify entry point against §10.1 rule 9 before
  anything else in that area. If it accepts a `cnf`-bound token without evidence, that
  is a defect to fix, as it was in Rust, and a Breaking entry in the CHANGELOG.
- Ship every test of §8 rule 7, each negative test with its I4 twin. Break each new
  behaviour once on purpose, and confirm the test meant to catch it goes red.
- `declines`, with the reason, for anything the SDK cannot ship: README and CHANGELOG,
  never a silent omission. CHANGELOG entries go under [Unreleased].
- Run every CI job locally, the way the workflow runs it. "The toolchain is
  unavailable" is a claim about a search: search twice before making it.
- Never skip, disable or quarantine a test. Never tag or publish. Never change an `alg`
  pin, a TLS policy, or §5 rule 3.
- When the PR is open, fill in its §8.1 row in axiam, subscribe to the PR and drive it
  to green.

Start by printing the list of what the port touches in <REPO>, file by file, then
begin with the re-vendor.
```

---

## 13. Open after PR G

Written at the end of PR G2 (S-7b, S-10b), when every server task of this plan
— S-1 … S-11 — and both console follow-ups have shipped. What remains is
below, one row per item, each with who takes it and what the next step is.
None of it is worked in PR G2.

| # | Item | Owner | Next step |
|---|---|---|---|
| 1 | **I₁ … I₁₁ → J**: the eleven SDK ports (C-1 … C-11) against **contract 1.51**, then the conformance review (C-12, now **1.52**). PR H (C-0) has landed its text: 1.51, because 1.50 was already `d5a6811`'s (C-0 EXECUTED, item 1) | Executing sessions: Opus 5 for C-1 and C-12; Sonnet 5 for C-2 … C-11 (§2) | C-1 (Rust, `ilpanich/axiam-rust-sdk`, branch `feat/contract-1.50` per §8 rule 2, or `feat/contract-1.51` if the maintainer renames it) re-vendors `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` from the **merged** PR H commit, then the ten ports per §8. The §27.10 manifest table assigns three defects to C-6, C-9, C-10 and C-11 on top of §6's scope. `check-sdk-artifact-drift.py` stays red (33 problems: three artefacts × eleven repositories) until they do; that is expected, not a regression |
| 2 | **Vault `sign_csr` of a `Server` certificate.** Refused under a `vault_pki` CA today, by design (S-7 EXECUTED, item 1): Vault's `sign-verbatim` takes SANs from the CSR only, and the CSR may not carry them | Maintainer decision, then an Opus 5 session (certificate issuance) | Decide whether to add the config key the plan excluded: a Vault role with `use_csr_sans=false`, so explicit names can reach the certificate. Until then `POST /certificates` (generate) is the path under a Vault CA, and the console says so |
| 3 | **D-7: X.509 `nameConstraints` in tenant CAs**, so the name fence holds for a relying party that never talks to AXIAM. T-288's residual | Next PKI pass; Opus 5 | A design note first: how a change to `server_cert_allowed_names` re-issues (or does not re-issue) a tenant CA, and what happens to leaves already issued under the old constraints |
| 4 | **The intermittent `500` from CA-certificate creation during e2e fixture setup**, deferred in S-5 as "a real unknown in CA generation; gets its own change" | Unassigned; its own change | Reproduce first: loop the matrix fixture's CA creation against a local stack and capture the server log for the `500`. No fix before there is a cause |
| 5 | **`k8s/frontend/deployment.yml`**: `readOnlyRootFilesystem: true` with no volume at `/etc/nginx/conf.d`, so the stock `20-envsubst-on-templates.sh` cannot render and the console most likely serves the base image's `default.conf` — no SPA fallback, no security headers, no proxying. Found in S-11 by reading the entrypoint; **not observed on a cluster** | Maintainer (deployment); a Sonnet 5 session can take the change | Observe it on a cluster (`kubectl exec … cat /etc/nginx/conf.d/default.conf`) before changing anything; if confirmed, mount an `emptyDir` at `/etc/nginx/conf.d` and add a probe that fails on the stock page |
| 6 | **Threat-model reconciliation**: `Axiam.json` is nine entries behind the STRIDE documents (flagged since PR A) | Maintainer | Write the nine missing entries into the Threat Dragon file from the text `threat-model-stride.md` already holds, then regenerate `website/src/threatModel.ts` and commit it, closing the gap `gen-threat-model.mjs` reports (279 in the JSON against 288 in the documents) |
| 7 | **D-3: widen the `has_role` key to (subject, role, resource)** | Maintainer decision (§7.1) | A design document of its own, with the data migration: verify no subject holds a role both globally and at a resource, and how "one global assignment" stays unique without a partial index |
| 8 | **D-4: mirror the management surface on gRPC** | Deferred | When taken: `ReactorAdminService` (`proto/axiam/v1/reactor.proto`) is the precedent; S-8's client-certificate verification is now in place for the listener it would ride on |
| 9 | **D-5, second round**: whether each excluded route family should accept a service-account token — self-service, organizations/tenants, settings, CA, PGP, SCIM, federation | Maintainer, argued family by family | One decision per family, each with the argument S-9 made for the eight it admitted; the route-map sweep in `m2m_management_test.rs` is where each decision is pinned |
| 10 | **D-6: a device access-token lifetime setting** | Deferred, only if the fleet cost turns out to be real | Measure first: handshake and token-issuance cost per device over a day, against the default 900 s lifetime |
| 11 | **§7.2's deliberate exclusions**: `webhooks` in the manifest; certificate-only authentication on gRPC; the `users` / `scopes` manifest tier in PHP, Swift, C and C++ | Deferred; C-0 records the tier gap in §27.10 | Each is taken when a consumer asks for it, not before |
| 12 | **§10: the feedback rows for the `axiam-domo-demo` findings document** — DF-001, DF-003, DF-004, DF-013, DF-014, DF-024, and the new DF-028 and DF-029 | Maintainer (edits that repository; a session does not) | Apply §10's table to `docs/dogfooding-findings.md` in `axiam-domo-demo` |

**Found during PR G2, not fixed there:**

| # | Item | Owner | Next step |
|---|---|---|---|
| 13 | `frontend/e2e/certificates.spec.ts`: the two older Generate-dialog tests probe once with `isVisible()` and look for labels the page does not have (`Common Name *`, `Key Type`), so they can pass only through their `else` branch and assert nothing about the dialog | Sonnet 5, test-only change | Rewrite them with auto-waiting assertions on the real labels (`Subject *`, `Key Algorithm`), as the Server tests next to them do |
| 14 | The settings lists edited as a textarea (DCR scopes, redirect hosts, audiences; CIMD domains) re-parse on every keystroke through `parseLines`, which drops a trailing newline, so starting a second line is awkward | Sonnet 5, console-only | Keep the raw text in form state and parse on save, or move them to the row editor `serverNamesPolicy.tsx` uses |

**Found during PR H, not fixed there** (C-0 is contract text only):

| # | Item | Owner | Next step |
|---|---|---|---|
| 15 | `POST /api/v1/admin/bootstrap` has **no rate limiter** (`server.rs`, no `build_governor` / `RateLimitShared`), unlike every other unauthenticated auth resource. It is gated on a setup token or an environment variable and is final after one success (`409`), so the exposure is a pre-bootstrap deployment reachable from the network | Maintainer decision; Sonnet 5 for the change (S-2's pattern) | Decide whether the window matters. If so, wrap it like `/auth/device` (S-2) with a small per-IP limit, add a knob to the human family, and record a threat entry |
| 16 | `/auth/device` answers **404**, not 401, when a presented certificate's tenant no longer exists: `handlers/auth.rs` looks the tenant up outside the extractor's 401 mapping. Separately, its spec entry lists 200 and 401 only. No limiter 429 is documented anywhere (S-2's choice; the one documented 429 is the resend-verification daily cap, a business rule), so the missing 429 is consistent, not a slip | Sonnet 5, server + spec | Map the missing tenant to the 401 its siblings get, with a test, and regenerate the spec. Whether limiter 429s belong in the spec at all is a maintainer decision for every route at once, not for this one |
| 17 | The SDK manifest defects §27.10 records: PHP never reconciles role grants or group bindings (docblock says it does); PHP, Swift, C and C++ never send `parent_id`; Swift, C and C++ default `resource_type` to `"folder"` | C-6, C-9, C-10, C-11 (with the 1.51 port) | Fix in the port, each with an idempotence test over a **nested** manifest that asserts the parent on the wire |

**References**

- [`claude_dev/remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) — §11 records, §12 gates, §13 fan-out rules
- [`claude_dev/issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) — the "cost, counted" form
- [`claude_dev/mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md) §2 — the model rule
- [`claude_dev/deny-override-design.md`](deny-override-design.md) — §2.2 precedence table, §5.1 the ancestor-clause warning, §6 out of scope
- [`claude_dev/rate-limit-posture-decision.md`](rate-limit-posture-decision.md) — G7
- [`claude_dev/decision-cache-decision.md`](decision-cache-decision.md) — cache key and invalidation levels
- [`claude_dev/crate-layering.md`](crate-layering.md) — for S-3's thumbprint helper
- `sdks/CONTRACT.md` §1, §5.2, §6.1, §10.3, §27.0, §27.6, §27.10, §28.11
