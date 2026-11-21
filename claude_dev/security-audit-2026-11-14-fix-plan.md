# Fix plan — security audit of 2026-11-14

> **Status: PLANNED — nothing executed yet. Open points closed with the owner
> on 2026-11-15 (§2).** Source report:
> [`security-audit-2026-11-14.md`](security-audit-2026-11-14.md). As each task
> lands, add an `EXECUTED` block at the head of its section (what shipped, which
> tests went in, what the plan did not anticipate), in the form
> [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) uses.

The audit produced **7 confirmed findings** (C1–C7), **21 leads that need
validation** (N1–N21) and about 90 hardening notes. This plan turns all 28
records into development tasks, folds the hardening notes that have a concrete,
low-risk fix into six further tasks, puts a review gate after every wave (§1.6), and lists explicitly what it leaves out and
why (§7).

Two properties of the report shape the plan:

1. **The N leads were never executed.** The audit could not build the Rust
   workspace. Every N task therefore starts by writing the report's validation
   test and watching it fail on unfixed code (§1.1). A lead that does not
   reproduce is recorded and closed, not "fixed".
2. **The report is a partial pass.** Fourteen coverage units were never hunted.
   That is audit work, not development, and it is out of scope here (§7).

---

## 1. Ground rules for every task

### 1.1 Validate first, then fix

For every task that carries an **N** lead:

1. Write the regression test described under *Validation plan → Local* in the
   report section for that lead. Assert the **secure** behaviour.
2. Run it against the unfixed code. It must **fail**. Record the observed
   result in the task's `EXECUTED` block.
3. If it **passes** on unfixed code, the lead did not reproduce. Stop. Change no
   production behaviour, keep the test as a pin, and report "not reproduced"
   with the evidence. Do not invent a fix for a defect you could not observe.
4. Otherwise implement the fix, re-run, and confirm the test passes.

For **C** findings the defect is already established: write the regression test,
confirm it fails, fix, confirm it passes.

### 1.2 Tests that pin today's vulnerable behaviour

The report names existing tests that assert the insecure result
(`bootstrap_test.rs:255`, `rbac_test.rs::org_settings_update_allows_org_settings_permission`,
`grpc_units.rs::get_user_success`). Rewrite them to the secure expectation. Never
delete or `#[ignore]` a test to get green.

### 1.3 Repositories, branches, commits

- Server work happens in `ilpanich/axiam`; each SDK task in its own
  `ilpanich/axiam-<lang>-sdk` repository.
- Work on the branch the executing session designates. Waves **stack on the
  same branch**: the next wave starts as soon as the previous wave's review gate
  (§1.6) is green, without waiting for a merge.
- One pull request per repository, opened when its first wave passes the gate
  and updated by every later wave. The owner merges when they choose.
- One **signed** commit per task, message `fix(security): <summary> (SA-NN, <finding>)`.
- Never commit to `main` directly.

### 1.4 Build hygiene (server)

Follow *Build & Disk Hygiene* in `CLAUDE.md` exactly: `cargo clean` between
tasks, narrowly scoped `cargo test -p <crate> --test <name>`, the swagger-ui
placeholder after every `target/` wipe, `apt-get install -y protobuf-compiler`
before anything that builds `axiam-server`, cargo's exit code captured from a
log and not from a pipeline. Run server tasks **sequentially**: they share one
`target/` and several touch the same files.

If a task changes a REST request or response type, regenerate
`sdks/openapi.json` with the procedure in `CLAUDE.md` in the same commit.

### 1.5 Definition of done (every task)

- Regression test added, observed failing before the fix and passing after.
- `cargo fmt -p <crate> -- --check` and `cargo clippy -p <crate> -- -D warnings`
  clean for each touched crate (or the SDK's own lint and test commands).
- No unrelated refactoring.
- `EXECUTED` block written into this document.

### 1.6 Review gate after every wave

No wave starts until the previous one has passed this gate.

1. When the last task of a wave is committed, run **two independent reviews**
   of the wave's complete diff, each by an **Opus 5.5** reviewer that wrote none
   of the code under review:
   - a **code-quality review**: correctness, error handling, test quality (does
     each regression test really fail without its fix?), clarity, duplication,
     adherence to the crate layering and to this plan's scope;
   - a **security review**: does each fix close its finding on every path, does
     it open a new one, are the fail-closed and upgrade-window behaviours right,
     did any secret, token or personal datum reach a log or an error message.
   The reviewers receive the diff, the task sections and the report sections —
   not the implementers' own summaries.
2. Wave 3 spans eleven repositories: review each repository's diff, and review
   the login-glue port (C6, C7) across the six SDKs for consistency with SA-20.
3. **Every finding must be resolved**, whatever its severity: either fixed, or
   rejected with a written justification. Nothing is carried to a later wave.
4. Fixes go to an agent on the model the original task used, one signed commit
   per review round: `fix(review): <summary> (wave N, round M)`.
5. After fixes, the same two reviews re-run on the changed code. The gate is
   green when both return no open finding.
6. Record the gate in this document under the wave's heading: the findings of
   each review, how each was resolved, and the number of rounds.

---

## 2. Decisions taken by this plan

These points had more than one defensible answer. The owner settled them on
2026-11-15; they are not to be reopened during execution.

| # | Finding | Decision | Alternative rejected |
|---|---|---|---|
| D-1 | N15 `require_role` reads OAuth scopes | SDKs stop mapping `scope` to roles. `require_role` reads only a `roles` claim and **fails closed** when it is absent. A separate `require_scope` helper is added. The server gains a `roles` claim (SA-18): the names of the subject's **global** roles in the tenant, emitted only when the client requested, and is allowed, the `roles` scope. | Always emitting the claim (every token grows, role names reach every client); a per-client flag (non-standard); deprecating `require_role`. |
| D-2 | N4 gRPC `UserService` has no RBAC | `GetUser` requires `users:get` unless the caller reads itself. `ValidateCredentials` is restricted to machine principals (`axiam:m2m`) holding a new `users:validate_credentials` permission. | Leaving it as "inter-service use": the listener accepts user tokens, so the label is not a control. |
| D-3 | N16 tenant `Suspended` is cosmetic | Suspension refuses sign-in, token issuance, refresh and API requests for the tenant's principals with `tenant_suspended`, and revokes live sessions and refresh tokens. Data is kept. Organization principals can still read and un-suspend the tenant. | Removing the status: it is already stored and exposed in the API. |
| D-4 | N13 SSRF pin vs. environment proxy | `pinned_client` calls `.no_proxy()` unconditionally. Guarded fetches never traverse an environment proxy. | Trusting the proxy: the destination would be chosen by the proxy's DNS, which is exactly what the pin exists to prevent. |
| D-5 | N21 SAML SP binding | Always compare `Recipient` on the form ACS **and** require `AudienceRestriction` containing the SP entity ID. No per-IdP opt-out. | Recipient only: the Web-SSO profile requires the audience, and an optional check is how this lead arose. |
| D-6 | N18 dev compose image | Point at the namespace `release.yml` publishes to and pin a released version. | Keeping `:latest`. |

| D-7 | N10 upgrade window | Access-token `typ` is **required from the first release that ships it**; an operator flag relaxes it for one rolling upgrade. | Lenient first, strict in the next minor release. |
| D-8 | C1 setup secret | The logged first-boot token stays the only setup secret. No new environment variable. | An operator-supplied `AXIAM_BOOTSTRAP_SETUP_TOKEN`. |
| D-9 | N2 SDK side | The seven SDKs with an AMQP transport verify the signed authz response within this plan (Wave 3). | Deferring SDK verification to a later conformance review. |
| D-10 | Hardening notes | Executed in this run as Wave 4, all six tasks. | A separate backlog. |

D-3 and D-5 change behaviour that a live deployment may rely on. Both get an
entry in the upgrade notes (SA-50).

---

## 3. Task overview

Model column: **Opus 5.5** where the task crosses several crates, defines a
contract other tasks port, or where a wrong fix opens a new hole; **Sonnet 5.5**
where the change is local and this plan specifies it completely.

### Wave 1 — server, principal boundaries (`ilpanich/axiam`, sequential)

| Task | Findings | Summary | Model |
|---|---|---|---|
| SA-01 | C1 | Bootstrap always requires the setup secret | Sonnet 5.5 |
| SA-02 | N1, N8, N9 | Organization-level guard on system audit, org settings, audit export | Opus 5.5 |
| SA-03 | N10 (+N14 server side) | Typed access tokens; purpose JWTs rejected | Opus 5.5 |
| SA-04 | N6 | `/oauth2/authorize` refuses client-minted user tokens | Sonnet 5.5 |
| SA-05 | N5 | mTLS device login checks service-account status | Sonnet 5.5 |
| SA-06 | N7 | Password reset/change deletes the stale OPAQUE record | Sonnet 5.5 |
| SA-07 | C3 | Dummy Argon2 hash uses production parameters | Sonnet 5.5 |
| SA-08 | N20 | Tenant predicate on group member counts | Sonnet 5.5 |

### Wave 2 — server, remaining leads (`ilpanich/axiam`, sequential)

| Task | Findings | Summary | Model |
|---|---|---|---|
| SA-09 | N11 | Erasure cancel restores the prior account status | Sonnet 5.5 |
| SA-10 | N13 | `pinned_client` ignores environment proxies | Sonnet 5.5 |
| SA-11 | N21 | SAML SP: mandatory Recipient and audience binding | Sonnet 5.5 |
| SA-12 | N4 | RBAC on gRPC `UserService` | Opus 5.5 |
| SA-13 | N16 | Enforce tenant suspension; revoke SCIM tokens on tombstone | Opus 5.5 |
| SA-14 | N3 | Signed envelope on mail and outbound AMQP queues | Opus 5.5 |
| SA-15 | N2 | Signed, per-producer authz responses | Opus 5.5 |
| SA-16 | N17, N18, N19 | Pinned actions, dev image, SurrealDB credentials out of argv | Sonnet 5.5 |
| SA-18 | N15 (D-1) | `roles` scope and claim in access tokens | Opus 5.5 |
| SA-17 | C5–C7, N2, N12, N14, N15 | CONTRACT 1.66 amendment (runs last in the wave) | Opus 5.5 |

### Wave 3 — SDKs (one task per repository, parallel)

| Task | Repository | Findings | Model |
|---|---|---|---|
| SA-20 | `axiam-typescript-sdk` | C7 and C6 **reference implementation**, N2, N14, N15 | Opus 5.5 |
| SA-21 | `axiam-python-sdk` | C6, C7, N2, N14, N15 | Sonnet 5.5 |
| SA-22 | `axiam-php-sdk` | C5, C6, C7, N2, N14, N15 | Sonnet 5.5 |
| SA-23 | `axiam-csharp-sdk` | C5, C6, C7, N2, N14, N15 | Sonnet 5.5 |
| SA-24 | `axiam-java-sdk` | C7, N2, N14, N15, C2 parity check | Sonnet 5.5 |
| SA-25 | `axiam-kotlin-sdk` | C6, C7, N12, N14, N15 | Sonnet 5.5 |
| SA-26 | `axiam-go-sdk` | C2, N2, N14, N15 | Sonnet 5.5 |
| SA-27 | `axiam-rust-sdk` | N2, N14, N15 | Sonnet 5.5 |
| SA-28 | `axiam-cplusplus-sdk` | C4, N14 | Sonnet 5.5 |
| SA-29 | `axiam-c-sdk` | N14 | Sonnet 5.5 |
| SA-30 | `axiam-swift-sdk` | N14 | Sonnet 5.5 |

SA-20 runs first; SA-21…SA-25 port its login-glue design and start when it is
done. SA-26…SA-30 do not depend on it and may start with SA-20.

### Wave 4 — hardening (`ilpanich/axiam`, sequential)

| Task | Summary | Model |
|---|---|---|
| SA-40 | REST edge matchers: dot segments, CSRF exemption, tenant selector | Sonnet 5.5 |
| SA-41 | OAuth2: PKCE downgrade, PAR burn, introspection session liveness | Sonnet 5.5 |
| SA-42 | SSRF guard: never-allowed addresses, host glob, IPv4-translated prefix | Sonnet 5.5 |
| SA-43 | MFA and WebAuthn: pending TOTP secret, setup-token guard, sign-in check, per-account counter | Opus 5.5 |
| SA-44 | Audit and gRPC: token redaction, `ValidateCredentials` audit row, message size, `/health/jobs` | Sonnet 5.5 |
| SA-45 | Deployment manifests: service-account token, ingress selector, loopback binds | Sonnet 5.5 |

### Wave 5 — close-out

| Task | Summary | Model |
|---|---|---|
| SA-50 | Threat model, upgrade notes, admin docs, final regression gate | Sonnet 5.5 |

**Totals:** 36 tasks — 10 on Opus 5.5, 26 on Sonnet 5.5 — plus, after each of
the five waves, the review gate of §1.6 (two Opus 5.5 reviews per round).

---

## 4. Wave 1 — server, principal boundaries

> **REVIEW GATE — PASSED (2026-11-20), 41 rounds.**
>
> **Shape.**
> - 21 review rounds (1, 3, 5 … 41). Each review round had one code-quality and one security review, both by Opus 5.5 reviewers who wrote none of the code.
> - 20 fix rounds, one signed commit each: `5a2d68d` … `7c0f1e9` (`fix(review): … (wave 1, round M)`).
> - Reviewers received the complete wave diff, this plan's §1–§4 and the report sections, plus the owner decisions below. They did not receive implementer summaries.
> - Every finding was fixed. None was rejected.
>
> **Owner decisions taken during the gate.** These were binding on later rounds.
> - **SA-02 system audit:** filter by the caller's organization, record the organization on new system-partition rows, and resolve it off the response path. Lookups are bounded by a semaphore and the permit is taken only for the datastore read. The admin UI gates the System-audit, organization Settings/Email tabs and the tenant View button exactly as the server does.
> - **SA-03 typed tokens:**
>   - a legacy `typ: JWT` counts as untyped;
>   - purpose tokens follow the relax flag;
>   - introspection is gated on `at+jwt`;
>   - logout tokens are typed `logout+jwt`;
>   - CONTRACT 1.67 §34.11 (e) records the wire changes, and the binding SDK rule lands in 1.68 with SA-17.
> - **SA-04 client-minted tokens:**
>   - OIDC scope consent, the account delete and export acts, every credential-management route, and every self-update are first-party only;
>   - own-account SCIM PUT, PATCH and DELETE and own-account `DELETE /users/{id}` are first-party only;
>   - an admin acting on another user is unchanged;
>   - a proposed unverified-address rule on reset was withdrawn.
> - **SA-06 credential epoch and version (N7):**
>   - Every credential write stamps `credential_changed_at`, written with the datastore clock, and bumps `credential_version` in one transaction. Directory accounts refuse credential writes in the repository.
>   - MFA challenge, MFA setup, WebAuthn state and `SealedLogin` artefacts carry the version and are judged by it alone. Only versionless artefacts fall back to the timestamp, and a tie refuses.
>   - The session mint checks the version in its transaction and re-reads it after commit.
>   - Session rows store the version (v119). Refresh rotation enforces it, and a legacy row refuses a change at or after its `created_at`.
>   - The OAuth2 refresh, authorization-code, device and CIBA grants refuse a credential change at or after the grant's time and re-check after minting. A device login that spans a change is refused (accepted and documented).
>   - Reset and change emit the SSF credential-change event and audit record even when revocation fails. A successful change notifies `PasswordChanged`.
>   - SCIM password writes return 400 `mutability` when OPAQUE is `required`.
>
> **Accepted residue (documented, not a defect).** The timestamp fallback for versionless MFA, WebAuthn and OPAQUE artefacts compares an application-clock `iat` with the datastore-clock stamp.
>
> **Stop rule changed by the owner (2026-11-20).** Round 41 was declared the final round, provided it found nothing of medium severity or higher. Lower findings are filed as GitHub issues instead of another fix round, and the run moves to the next wave. This replaces item 3 of §1.6 for findings below medium, from this gate onward.
>
> **Round 41 outcome.**
> - Security review: no findings.
> - Code-quality review: two low findings and one nit, all on tests or docs, none a behaviour defect. Each was filed with the label `wave-1-review-follow-up`:
>   - **QR22-1 (low)**, #872: the same-second, after-epoch acceptance of unversioned tokens is no longer covered by a test.
>   - **QR22-2 (low)**, #873: OPAQUE `login/finish` duplicates the credential-superseded rule, and no test covers it.
>   - **QR22-3 (nit)**, #874: the first SA-06 paragraph of the deployment guide presents the timestamp check as the rule for current tokens.
>
> **Leads.** All eight Wave 1 leads (N1, N5, N6, N7, N8, N9, N10, N20) reproduced. C1 and C3 were confirmed findings.
>
> **Carried forward, outside Wave 1's scope.**
> - SA-17 bumps CONTRACT to 1.68 with the typ/purpose/kid rule.
> - Logout tokens without a `kid` (§12.4) are not yet addressed.
> - The `allow_missing_aud_as_user` default change is not yet recorded.
> - The plan's "1.66" reference is stale.
> - SDKs re-sync to CONTRACT 1.67 in Wave 3.
> - OAuth2 introspection may still report a surviving pre-change refresh token as active (SA-41).

### SA-01 — Bootstrap always requires the setup secret (C1)

> **EXECUTED (2026-11-15, Sonnet 5.5).** `bootstrap()` now treats
> `AXIAM_BOOTSTRAP_ADMIN_EMAIL` as an additional restriction only (mismatch →
> 403) and requires a valid, unconsumed `setup_token` on every path; the token
> hash is always consumed in the bootstrap transaction (`consumed_token_hash` is
> no longer an `Option`). No new environment variable (D-8).
>
> - **Regression test:** `bootstrap_test::bootstrap_email_gate_still_requires_setup_token`
>   (email set: no token → 403, garbage token → 403, valid token + wrong email →
>   403, valid token + right email → 201). Unfixed code: `FAILED … left: 201
>   right: 403` at the first assertion. Fixed: passes. Control
>   `bootstrap_valid_token_without_email_gate_succeeds` (email unset + valid
>   token → 201) passes before and after. Whole file: 15 passed.
> - **Rewritten tests:** every email-only bootstrap test, including
>   `bootstrap_creates_org_tenant_admin`, now mints and sends a token (helpers
>   `first_boot_token`, `post_bootstrap_status`).
> - **Not anticipated:** (1) `bootstrap_returns_409_after_admin`: the second
>   sequential call now answers **403**, not 409, because the first call
>   consumed the token and the gate runs before the lock — the same behaviour
>   the email-unset path already had. The test asserts 403 and exactly one
>   user; the 409 lock path stays covered by `bootstrap_concurrent_race_single_admin`.
>   (2) Token extraction lives in one new helper, `scripts/first-boot-token.sh`,
>   used by `scripts/e2e-bootstrap.sh` (CI and examples-smoke call it; no
>   workflow change) and `benchmarks/runner/seed.sh`, which bootstrapped by
>   email only. `infra/rpi5-k3s/scripts/03-axiam-bootstrap.sh` no longer falls
>   back to email-only. (3) Doc-comment changes moved `sdks/openapi.json`
>   (regenerated; digest checked) and two sentences of `sdks/CONTRACT.md`
>   (bootstrap rows; no version bump) — both re-sync downstream with SA-17.
> - Docs: `docs/admin/README.md`, `docs/deployment/README.md`,
>   `docs/deployment/rpi5-k3s.md`, the k8s ConfigMap and e2e/bench compose
>   comments, the first-boot log text in `main.rs`, the `BootstrapPage` hint.

- **Model:** Sonnet 5.5. One handler, the fix is sketched in the report.
- **Files:** `crates/axiam-api-rest/src/handlers/bootstrap.rs` (280–320),
  `crates/axiam-api-rest/tests/bootstrap_test.rs`, `crates/axiam-server/src/main.rs`
  (~530, log text), `docs/admin/README.md`, the k8s ConfigMap comment, the e2e compose file.

Instructions:

1. Restructure the gate so that `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, when set, is an
   **additional** restriction: mismatch → 403. Then, on every path, require
   `setup_token`, hash it, check `setup_token_is_valid`, and set
   `consumed_token_hash`. Follow the report's sketch.
2. Add **no** new environment variable (D-8): the token printed once in the
   first-boot log remains the only setup secret.
3. Update every test helper that bootstraps by email only so that it passes a
   token. The e2e stack and any bootstrap script must read the token from the
   server's first-boot log; adapt them and keep the extraction in one helper.
4. Correct the wording in `docs/admin/README.md` that calls the email variable
   sufficient, and the first-boot log text. State in the Kubernetes and compose
   guides how the operator retrieves the token from the log, and that first-boot
   logs are secret until bootstrap completes.

Tests: email set + no token → 403; email set + garbage token → 403; email set +
valid token + wrong email → 403; email set + valid token + right email → 201;
email unset + valid token → 201. Rewrite `bootstrap_creates_org_tenant_admin`.

### SA-02 — Organization-level guard on three handlers (N1, N8, N9)

> **EXECUTED (2026-11-15, Opus 5.5). N1, N8, N9: all reproduced.**
> `audit_logs:list_system`, `organizations:get_settings`,
> `organizations:update_settings` and `tenants:export_audit` joined
> `ORGANIZATION_LEVEL_ACTIONS`. `require_organization_principal` guards
> `audit::list_system`, `settings::{get,set}_org_settings` and
> `email_config::get_org_email_config`; `require_organization_principal_for_tenant`
> guards `tenants::get` and `tenants::export_audit`.
>
> - **Validation (unfixed → fixed):**
>   N1 `audit_test::standard_tenant_admin_cannot_read_the_system_audit_partition`:
>   `left: 200 right: 403` (body held B's `POST /scim/v2/Users` row) → ok.
>   N8 `rbac_test::standard_tenant_admin_cannot_rewrite_the_org_baseline` and
>   `…_cannot_read_the_org_baseline`: `200` vs `403` → ok.
>   N9 `tenant_test::standard_tenant_admin_cannot_export_a_sibling_tenants_audit_trail`,
>   `…_cannot_read_a_sibling_tenant`,
>   `a_restricted_organization_principal_exports_only_the_tenants_it_reaches`:
>   `200` vs `403` → ok. Unfixed runs: handlers and `permission_scope.rs`
>   stashed, tests in place.
> - **Step 4 — no migration needed.** The server reconciles default-role grants
>   at every boot (`main.rs:630` → `seeder.rs:839`
>   `reconcile_default_role_grants`, revoke at `seeder.rs:992` driven by
>   `is_organization_level_action`), so extending the list revokes the four
>   actions from existing Standard tenants' super-admin and admin roles.
>   Pinned by `seeder_default_data_test::reconcile_revokes_the_sa_02_actions_from_an_existing_ordinary_tenant`
>   (unfixed: `revoked: 0`, expected 8) and
>   `the_sa_02_actions_are_withheld_from_a_new_ordinary_tenant`. Limit: a
>   custom role an operator granted one of these keeps the row; the handler
>   guard refuses it (tested through the "explicit grant" caller).
> - **Step 3:** the org email-config setters (`set_`, `delete_`,
>   `test_org_email_config`) were already guarded; only the getter was not.
>   `email_config:read`/`:write` are shared with the tenant handlers, so neither
>   joins the list (the scope guard is the control there).
> - **Step 5:** `organization_scope_consistency_test` now carries
>   `ORGANIZATION_ROUTES` (all 25 `/organizations/{org_id}` routes, method,
>   path, handler, guard; five GET routes `Exempt` with a reason).
>   `every_organization_route_is_on_the_guard_list` compares it with
>   `server.rs` both ways (checked by adding a probe route: FAILED, then
>   reverted); `every_listed_organization_route_reaches_its_guard` failed on
>   the five unguarded handlers before the fix.
> - **Step 6:** `rbac_test::org_settings_update_allows_org_settings_permission`
>   now uses a user of the organization's scope tenant.
> - **Not anticipated:** 20 existing tests in `settings_test`, `cimd_test`,
>   `dynamic_registration_test`, `directory_config_test`, `gdpr_handlers_test`
>   and `ssf_shared_issuer_test` wrote the org settings with an ordinary-tenant
>   token; each now uses a scope-tenant token for that request only.

- **Model:** Opus 5.5. This is the highest-value boundary in the report, the
  existing tests pin the wrong behaviour, and already-seeded tenants hold the
  permissions.
- **Files:** `crates/axiam-core/src/permission_scope.rs` (`ORGANIZATION_LEVEL_ACTIONS`, ~64),
  `crates/axiam-db/src/seeder.rs` (~527),
  `crates/axiam-api-rest/src/handlers/{audit.rs,settings.rs,tenants.rs,email_config.rs}`,
  `crates/axiam-api-rest/src/org_scope.rs` (67, 199),
  `crates/axiam-api-rest/tests/{organization_scope_consistency_test.rs,rbac_test.rs,tenant_test.rs}`.

Instructions:

1. Validate first (§1.1) with the three two-tenant tests in the report: A's
   seeded admin reads `/api/v1/audit-logs/system`; writes
   `PUT /organizations/{org}/settings`; calls
   `POST /organizations/{org}/tenants/{B}/audit-export` and
   `GET /organizations/{org}/tenants/{B}`.
2. Add `audit_logs:list_system`, `organizations:update_settings`,
   `organizations:get_settings` and `tenants:export_audit` to
   `ORGANIZATION_LEVEL_ACTIONS`. Check the email-config action names and add the
   organization-level ones.
3. Add `require_organization_principal` to `list_system`, `set_org_settings`,
   `get_org_settings`, `get_org_email_config` and its setter; add
   `require_organization_principal_for_tenant(&user, &state, path.tenant_id)` to
   `export_audit` and `tenants::get`. The handler guard is the control; the
   seeder change is defence in depth.
4. Existing deployments: the seeder now withholds these actions from new
   Standard tenants. Check whether the seeder reconciles existing role grants on
   boot. If it does not, add an idempotent migration that removes the four
   actions from Standard-tenant roles, and say so in the `EXECUTED` block.
5. Extend `organization_scope_consistency_test.rs` with an explicit list of
   every `/organizations/{org_id}/**` route; the test fails when a route on the
   list reaches its handler without one of the two guards. A new organization
   route that is not on the list must also fail the test.
6. Rewrite `org_settings_update_allows_org_settings_permission` to use an
   organization-scope principal.

### SA-03 — Typed access tokens (N10, server side of N14)

> **EXECUTED (2026-11-15, Opus 5.5). N10: reproduced** (discoverable and
> second-factor WebAuthn state tokens accepted by `validate_access_token`, the
> gRPC `AuthInterceptor` and `ValidateToken`). Every access token is signed
> with `typ: at+jwt` and a `kid` through the single `sign_claims` path; purpose
> tokens go through a new `sign_purpose_token`, which refuses `at+jwt` and
> `JWT`. `decode_access_token` **and** `decode_access_token_any_audience`
> (introspection) apply `check_access_token_type` (typ rule + `purpose` rule).
> `require_access_token_typ` (`AXIAM__AUTH__REQUIRE_ACCESS_TOKEN_TYP`) defaults
> to `true`; `allow_missing_aud_as_user` now defaults to `false`. Documented in
> `docs/deployment/README.md` ("Access-token type … and upgrading"), with a
> startup warning when the flag is off.
>
> | Token | `typ` | `kid` |
> |---|---|---|
> | Access (user, client credentials, service account, RPT, exchange) | `at+jwt` | yes |
> | OIDC ID token | `JWT` | yes |
> | WebAuthn state | `axiam-webauthn-state+jwt` | no (wave 1 review S-8) |
> | MFA challenge / MFA setup | `axiam-mfa-challenge+jwt` / `axiam-mfa-setup+jwt` | no (wave 1 review S-8) |
> | Back-channel logout | `logout+jwt` (new) | no |
> | SSF SET | `secevent+jwt` (unchanged) | yes |
>
> - **Regression tests (unfixed → fixed):**
>   `webauthn_single_use_test::n10_a_discoverable_state_token_is_not_an_access_token`,
>   `…n10_a_second_factor_state_token_is_not_an_access_token` (FAILED: "state
>   token was accepted as an access token: Ok(…)") → ok;
>   `grpc_units::n10_the_interceptor_refuses_a_webauthn_state_token`,
>   `…n10_validate_token_reports_a_webauthn_state_token_invalid` (FAILED,
>   subject nil UUID) → ok; `webauthn::tests::the_state_verifier_requires_the_state_typ`
>   (rule 6; FAILED: accepted `at+jwt`) → ok;
>   `auth_service_test::sa03_mfa_purpose_tokens_are_typed_and_are_not_access_tokens`,
>   `…sa03_an_access_token_is_refused_by_the_mfa_verifiers` (FAILED on `typ`) → ok.
>   Positive controls pass: REST, gRPC, `token_exchange_test`, `uma_test`
>   (`claim_token`). The gRPC N10 tests set `allow_missing_aud_as_user: true`
>   so that the type, not the new aud default, is what refuses.
> - **MFA challenge/setup → access token: not reproduced as an acceptance**
>   (no `jti`, so deserialisation already failed); typed anyway per step 2, tests kept as pins.
> - **Rewritten:** `config_tests::default_has_sane_values` (now asserts
>   `allow_missing_aud_as_user == false`, `require_access_token_typ == true`).
> - **Not anticipated:** (1) Every pre-SA-03 token carried `typ: "JWT"`
>   (`jsonwebtoken::Header::new`), not an absent `typ`. Absent and `JWT` are
>   both treated as "untyped": refused in strict mode, accepted in relaxed
>   mode only without `purpose`; any other `typ` is refused in both modes.
>   (2) Purpose verifiers follow the same flag, so in-flight ceremonies survive
>   a relaxed rolling upgrade. (3) Introspection reports purpose tokens
>   inactive. (4) Logout tokens gain `typ: logout+jwt` (OIDC Back-Channel
>   Logout §2.4). (5) `logout::decode_id_token_hint` (also used by `/oauth2/authorize`)
>   and `ciba::verify_id_token_hint` originally checked no `typ`; since the
>   wave 1 review (Q-8/S-10) both accept only `JWT` or an absent `typ`. (6) Upgrade effect for SA-50: under the strict default
>   every session re-authenticates or refreshes within one access-token
>   lifetime (15 min).

- **Model:** Opus 5.5. Token validation is shared by REST, gRPC, token exchange
  and UMA; a mistake either locks out valid tokens or leaves the hole open.
- **Files:** `crates/axiam-auth/src/token.rs` (`decode_access_token`, 1714–1718,
  and every mint site), `crates/axiam-auth/src/config.rs` (739,
  `allow_missing_aud_as_user`), `crates/axiam-auth/src/webauthn.rs` (653, 658),
  the MFA-challenge and setup-token mint sites in `crates/axiam-auth/src/service.rs`,
  `crates/axiam-api-grpc/src/middleware/auth.rs`, the test files that reference
  `allow_missing_aud_as_user`.

Instructions:

1. Validate first: `start_discoverable_authentication` and `start_authentication`
   state tokens pass `validate_access_token`; the same token passes the gRPC
   `AuthInterceptor` and `TokenServiceImpl::validate_token`.
2. Mint every access token with JOSE header `typ: at+jwt` (RFC 9068). Mint every
   purpose token (WebAuthn state, MFA challenge, MFA setup, any other JWT signed
   with the access-token key — enumerate them all with a search for the signing
   call) with its own distinct `typ`, for example `axiam-webauthn-state+jwt`.
3. `decode_access_token` rejects a token when (a) the header `typ` is present
   and is not `at+jwt` (compare case-insensitively, accept `application/at+jwt`),
   or (b) the claims contain `purpose`. Rule (b) is what protects during a
   rolling upgrade, when tokens minted by the previous version have no `typ`.
4. Strict by default (D-7): add `require_access_token_typ`, default **`true`**.
   An access token without `typ` is refused. An operator may set the flag to
   `false` for one rolling upgrade; in that mode a `typ`-less token is accepted
   only if it carries no `purpose` claim. Document the flag and the 15-minute
   re-authentication effect of leaving it at the default.
5. Default `allow_missing_aud_as_user` to `false`. Update the tests that depend
   on the old default by setting it explicitly.
6. Each purpose-token verifier must require its own `typ` once minted with one,
   so an access token cannot be replayed as a ceremony state token either.

Tests: the validation tests now refuse; a normal access token still passes on
REST, gRPC, token exchange and UMA `claim_token`; an access token is refused by
each purpose-token verifier.

### SA-04 — `/oauth2/authorize` refuses client-minted user tokens (N6)

> **EXECUTED (2026-11-15, Sonnet 5.5). N6: reproduced.**
> `resolve_authorize_principal` gains an arm before Path 1: a principal whose
> token `minted_for_client()` becomes an `AuthenticationFailed` and flows into
> the anonymous Path 2 — 302 to `/login?return_to=…` for a `browser_sso`
> client, the ordinary anonymous 401 otherwise; never 403.
>
> - **Regression tests** (`oauth2_login_hop_test`, real tokens: confidential X
>   via the code flow, public PKCE client Y):
>   `n6_a_client_minted_token_does_not_authorize_another_client` (bearer)
>   unfixed `FAILED: must fall through to the login page:
>   https://rp.example.com/callback?code=…` → ok;
>   `n6_a_client_minted_token_in_the_access_cookie_does_not_authorize`
>   (same token in `axiam_access`) FAILED → ok.
> - **Controls:** `n6_control_a_first_party_session_cookie_still_authorizes`
>   ok before and after; existing
>   `a_token_bearing_request_is_unaffected_and_ignores_the_tenant_parameter`
>   (console bearer token) and the `axiam_op_session` hop tests pass. Ten
>   oauth2 test files pass (243 tests).
> - **Not anticipated:** the cookie-borne variant is closed by the same arm.
>   The refresh-token half of the report's chain was not exercised: code
>   issuance is the gating step.

- **Model:** Sonnet 5.5. The rule exists (`minted_for_client`,
  `extractors/auth.rs:414`); it has to be applied in one more place.
- **Files:** `crates/axiam-api-rest/src/handlers/oauth2.rs`
  (`resolve_authorize_principal`, 653–664), `extractors/auth.rs`.

Instructions: validate with the report's two-client flow (confidential X,
public Y, bearer X-token on `/oauth2/authorize` for Y). Then apply the same
refusal that `device.rs` (ConsoleSignIn) and `ciba_approval.rs` apply: a
token-borne principal whose token was minted for an OAuth2 client is not an
authorization. Treat the request as **anonymous** (fall through to the login
redirect) and do not return 403, so a browser that happens to send a stale
header still reaches the login page. First-party session cookies must keep
working: add a control test for that.

### SA-05 — mTLS device login checks service-account status (N5)

> **EXECUTED (2026-11-15, Sonnet 5.5). N5: reproduced.** `device_auth` loads
> the bound service account and answers 401 ("the service account bound to
> this certificate is not active") when it cannot be loaded or its status is
> not `Active`, mirroring `network_decide.rs`. It also inserts
> `AuditAttribution` for the proven tenant, so the refusal (and success) row is
> written under that tenant rather than the nil partition.
>
> - **Regression test:** `device_auth_test::device_auth_refuses_a_non_active_service_account`
>   (Inactive, Locked, PendingVerification in turn; 401, no `access_token`, an
>   audit row with `http_status` 401 under the tenant; control: reactivated →
>   200 with `sub` = the account). Unfixed: `FAILED … a Inactive service account
>   must not be issued a device token … left: 200 right: 401`. Fixed: ok;
>   `device_auth_test` 15 passed, `device_login_rate_limit_test` 6 passed.
> - **Not anticipated:** the file's `test_app!` now wraps the app in
>   `AuditMiddleware`. The OpenAPI 401 description was left unchanged (no spec
>   change). `axiam-server`'s `radius_e2e.rs` was not run.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-api-rest/src/handlers/auth.rs` (`device_auth`, 934–976),
  `crates/axiam-api-rest/tests/device_auth_test.rs`.

Instructions: validate (disable the bound service account, call
`POST /api/v1/auth/device`, expect a token today). Fix by loading
`service_account_repo.get_by_id(cert_auth.tenant_id, cert_auth.service_account_id)`
and returning 401 unless `status == UserStatus::Active`, mirroring
`network_decide.rs:362–368`. Write an audit row for the refusal.

### SA-06 — Password reset and change retire the stale OPAQUE record (N7)

> **EXECUTED (2026-11-15).** N7 **reproduced** for password reset and for
> self-service change: on unfixed code, under `opaque_mode=optional`, OPAQUE
> login with the pre-reset/pre-change password returned 200.
> Fix: `SurrealUserRepository::update` (`crates/axiam-db/src/repository/user.rs`)
> deletes the user's `opaque_credential` row in the same SurrealDB transaction
> as any write of `password_hash`. Every writer of the hash — reset
> (`PasswordResetService::confirm_reset`), change (`AuthService::change_password`)
> and SCIM password PATCH — goes through that call, so one rule covers all of
> them. Admin create and bootstrap create a user with no prior record; directory
> linking already deleted the record; no login-time rehash of user passwords
> exists. Deviation from the letter of the plan: the delete is unconditional on a
> hash write rather than only when `enrolled` is `None`; when a new record is
> supplied, `store_credential` upserts it immediately after (both handlers call
> it after the hash update), so the outcome is identical on success, and on an
> upsert failure the user is left with no record rather than one answering to the
> old password. Tests: `opaque_login_test.rs`
> `n7_a_reset_without_a_record_retires_the_old_opaque_record`,
> `n7_a_change_without_a_record_retires_the_old_opaque_record` (FAILED before,
> `left: 200 right: 200`; pass after), controls
> `n7_control_a_reset_with_a_new_record_keeps_it`,
> `n7_control_a_change_with_a_new_record_keeps_it`; `opaque_coverage_test.rs`
> `writing_the_password_hash_retires_the_opaque_record`,
> `writing_the_hash_and_the_email_together_retires_the_record` (FAILED before,
> pass after), `an_update_that_leaves_the_hash_alone_keeps_the_record`. SCIM is
> covered at the repository level only (no SCIM end-to-end test).

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-api-rest/src/handlers/opaque_enrollment.rs`
  (`store_credential`, 154–162), `password_reset.rs` (376), the
  `change_password` handler in `auth.rs` (~1471),
  `crates/axiam-api-rest/tests/opaque_login_test.rs`.

Instructions: validate with the report's test (`opaque_mode=optional`, reset
without an `opaque` field, OPAQUE login with the old password). Fix: when
`enrolled` is `None` and a record exists, call
`opaque_credential_repo.delete_for_user` inside the same transaction as the hash
update. Cover reset, self-service change and any admin set-password path — find
every writer of the Argon2 hash and apply the same rule.

### SA-07 — Dummy Argon2 hash uses production parameters (C3)

> **EXECUTED (2026-11-15).** `crates/axiam-auth/src/password.rs`: new
> `production_params()` (m=19456, t=2, p=1) is the single source used by
> `hash_password`; the `DUMMY_HASH` constant (m=65536, t=3, p=4) is replaced by
> `dummy_hash()`, a process-wide `OnceLock<String>` filled by `hash_password` on a
> random UUID. `equalising_dummy_verify` still goes through `verify_password` with
> the configured pepper, so the dummy does the same work as a real wrong-password
> verify with or without a pepper (the pepper is a prefix, not a pre-hash). The
> `OnceLock` init uses `expect`: its only failure paths are statically valid
> params and a hash of a short random value. Doc comments in `password_reset.rs`
> and `service.rs` updated (they named the removed constant). Test:
> `password::tests::the_dummy_hash_uses_the_production_argon2_parameters` —
> FAILED before (`memory cost left: 65536 right: 19456`), passes after
> (`axiam-auth --lib`: 292 passed, 0 failed). No other hard-coded Argon2 PHC
> strings or production parameters exist in `crates/`.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-auth/src/password.rs` (22, 43, 53).

Instructions: introduce `production_params()` used by `hash_password`; replace
the `DUMMY_HASH` constant with a process-wide `OnceLock<String>` produced by
`hash_password` on a random value, as sketched in the report. Mind the pepper:
the dummy must be hashed and verified the same way a real hash is. Unit test:
the parameters parsed from the dummy hash equal `production_params()`.

### SA-08 — Tenant predicate on group member counts (N20)

> **EXECUTED (2026-11-15).** N20 **reproduced** for both functions: with a
> tenant-B group of three members, `get_members(A, group_id)` and
> `get_service_account_members(A, group_id)` returned empty items but
> `total == 3`. Fix (`crates/axiam-db/src/repository/group.rs`): both count
> queries now require `out.tenant_id = $tenant_id AND in.tenant_id = $tenant_id`
> (the `member_of` edge has no tenant column; the predicate sits on its
> endpoints) and bind `$tenant_id`. Tests in `group_repository_test.rs`:
> `get_members_total_does_not_leak_other_tenant_count`,
> `get_service_account_members_total_does_not_leak_other_tenant_count` — FAILED
> before (`left: 3, right: 0`), pass after (11 passed); each includes a
> same-tenant control (`total == 3`). The other count queries in `group.rs`
> already filter on `tenant_id`.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-db/src/repository/group.rs` (`get_members`,
  `get_service_account_members`).

Instructions: validate (group in tenant B with three users, call
`get_members(A, group_id)`, expect `total == 3` today). Add the tenant predicate
to both count queries and bind `$tenant_id`, matching the data query beside each.

---

## 5. Wave 2 — server, remaining leads

### SA-09 — Erasure cancel restores the prior status (N11)

> **EXECUTED (2026-11-20, Sonnet 5.5). N11: reproduced.** On the unfixed code a
> `Locked`, `Inactive` or `PendingVerification` account read `Active` after an
> erasure request was cancelled. `create_with_pending_flag` now reads the user's
> status inside its transaction, before parking the account as `Inactive`, and
> stores it on the request as `prior_status`; `cancel_tx` restores
> `prior_status ?? 'Active'`. Schema **v120** (`account_deletion_prior_status`)
> adds the one optional column — additive, no `DEFAULT`, no backfill: a request
> written before v120 has none and restores `Active`, as every cancel did before.
> No domain struct, REST type or OpenAPI change.
>
> Regression tests (`crates/axiam-db/src/repository/account_deletion.rs`):
> `cancel_restores_prior_status_{locked,inactive,pending_verification}` failed
> before the fix (`left: Active`) and pass after; `cancel_restores_prior_status_active`
> and `cancel_of_a_legacy_row_without_prior_status_restores_active` pin the
> unchanged cases; `schema::tests::v120_adds_only_the_optional_prior_status_column`.
> `cargo test -p axiam-db --lib` 357 passed; the account-deletion integration
> suites (`deletion_cancel_race_test`, `owed_erasure_claim_test`,
> `provisioning_sink_test`, `gdpr_handlers_test`, `gdpr_test`) pass; fmt and
> clippy clean.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-db/src/repository/account_deletion.rs` (211–215,
  370–372), `crates/axiam-db/src/schema.rs`.

Instructions: validate for prior status `Locked`, `Inactive` and
`PendingVerification`. Add a `prior_status` field to the `account_deletion` row,
written in `create_with_pending_flag` inside the existing transaction, and
restore it in `cancel_tx`. Rows created before the change have no value: restore
`Active` for those, as today, and note it. One regression test per prior status.

### SA-10 — Guarded HTTP client ignores environment proxies (N13, D-4)

> **EXECUTED (2026-11-20, Sonnet 5.5). N13: reproduced.** With `HTTPS_PROXY`
> pointing at a loopback fixture, the unfixed `pinned_client` sent
> `CONNECT rebind.example.test:443` to the proxy: the destination was named by
> hostname and the validated IP no longer decided it. `pinned_client` now calls
> `.no_proxy()` unconditionally (D-4). Regression test
> `ssrf::tests::n13_pinned_client_ignores_environment_proxy` failed before and
> passes after; `cargo test -p axiam-pki --lib` 152 passed. The deployment
> guide ("Outbound SSRF guard — same-network IdPs") now says guarded fetches
> ignore `HTTP(S)_PROXY`/`ALL_PROXY`.
>
> Every fetch of a tenant-, admin- or IdP-supplied URL goes through
> `guarded_fetch*` and therefore `pinned_client`: webhooks, back-channel logout,
> SSF push, CIBA ping, CIMD, JWKS, OIDC discovery and token exchange, OAuth2
> social endpoints, SAML SP/IdP metadata, SCIM outbound, e-mail HTTP providers,
> FIDO MDS. Clients that do **not** use `pinned_client` (none fetches a
> tenant-supplied URL; listed per the instructions, not changed): the shared
> `http_client` (`axiam-server/src/boot.rs` ~1297) and the `reqwest::Client::new()`
> defaults in `axiam-api-rest/src/state/mod.rs` (~375, 834, 911, 1017) — handed
> to the federation constructors but used only for the HIBP check;
> `axiam-auth/src/policy.rs` ~197 (HIBP range API, fixed host); the Vault clients
> in `axiam-pki/src/ca_key_store.rs` ~201, `axiam-auth/src/secrets.rs` ~274 and
> `axiam-pki/src/vault_pki.rs` (operator-configured address); the local health
> probe `axiam-server/src/healthcheck.rs` ~106. These keep env-proxy discovery.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-pki/src/ssrf.rs` (`pinned_client`, 251–257).

Instructions: validate with the loopback CONNECT-proxy fixture from the report.
Add `.no_proxy()` to the builder. Find every other `reqwest::Client` that
fetches a tenant-supplied URL and confirm it goes through `pinned_client`; list
any that does not in the `EXECUTED` block without fixing it. Add a line to the
admin network documentation: guarded fetches do not use an egress proxy.

### SA-11 — SAML SP: mandatory Recipient and audience binding (N21, D-5)

> **EXECUTED (2026-11-20, Sonnet 5.5). N21: reproduced.** In the form-ACS
> argument shape (no expected destination), a correctly signed assertion with no
> `AudienceRestriction` and a `Recipient` naming another SP was accepted; so was a
> no-audience assertion with the correct `Recipient`: the audience check ran only
> when the element was present. `saml.rs` now rejects `<Conditions>` with an
> absent or empty `AudienceRestriction`, and still requires the SP entity ID among
> the audiences (D-5, no opt-out). `saml_acs_form_public` passes
> `login_state.idp_redirect_uri.as_deref()` (the ACS URL the SAML start stored, as
> the JSON ACS already used), so `Response@Destination` and the signed
> `SubjectConfirmationData@Recipient` are compared on both ACS paths.
> Six tests in `saml::tests`: `form_acs_shape_rejects_no_audience_foreign_recipient_assertion`
> and `assertion_without_audience_restriction_is_rejected` failed before and pass
> after; `assertion_with_foreign_audience_is_rejected`,
> `form_acs_with_expected_destination_{rejects_foreign_recipient,accepts_conformant_assertion}`
> and `nameid_with_interior_comment_parses_to_full_text` (hardening notes) pin
> behaviour that was already correct. `generate.sh` gained an audience-block
> argument and three fixtures; the script mints a fresh key, so the whole fixture
> set and `signing_cert.pem` were re-signed (content and audiences unchanged).
> After: `axiam-federation` 418 lib tests; REST `federation_test` 87,
> `sec095_federated_login_gate_test` 6, `saml_idp_e2e_test` 10,
> `saml_idp_sso_test` 22, `saml_admin_test` 38; `axiam-server` `req5_saml_e2e` 9;
> SAML-off `cargo check` clean. **Upgrade note for SA-50:** an IdP that omits
> `AudienceRestriction` for the SP entity ID is now refused.

- **Model:** Sonnet 5.5.
- **Files:** `crates/axiam-federation/src/saml.rs` (636, 1483),
  `crates/axiam-api-rest/src/handlers/federation_login.rs` (1331).
- **Build note:** needs the `saml` feature and system libxml2 headers; install
  them, do not use `--no-default-features` for this task.

Instructions: validate with the report's fixture (no `AudienceRestriction`,
foreign `Recipient`). Pass `login_state.idp_redirect_uri.as_deref()` as the
expected destination on the form ACS. In `saml.rs:636` reject an assertion with
no `AudienceRestriction`, and one whose audiences do not include the SP entity
ID. Add the SAML test from the hardening notes: a NameID with an interior XML
comment parses to its full text.

### SA-12 — RBAC on gRPC `UserService` (N4, D-2)

> **EXECUTED (2026-11-20, Opus 5.5). N4: reproduced.** A same-tenant
> `axiam:user` token whose subject held no grant read another user's username,
> email and status through `GetUser`; `ValidateCredentials` answered
> (`valid: true`) for a user token and for a service account with no permission,
> and wrote no audit row. Now `GetUser` requires `users:get` (resource nil, as
> REST) unless `claims.sub == user_id`. `ValidateCredentials` first refuses any
> caller that is not a service account, by REST's own machine-principal rule
> (`aud == axiam:m2m` **and** `sub_kind == ServiceAccount`, so a user token
> narrowed to `axiam:m2m` by exchange is refused too), then requires the new
> `users:validate_credentials`; both run before the lookup, the hash permit and
> lockout accrual. Every answered call writes one `auth.credentials_validated`
> row (Success/Failure, service-account actor, matched user as resource, peer
> IP; the presented name is not recorded); refused callers write none.
> The permission is registered in `permissions.rs` and listed in the new
> `axiam_db::seeder::SEEDED_TO_NO_ROLE`, which both seeding and reconciliation
> skip (an operator's explicit grant is kept). The engine is injected as a third
> gRPC `AuthorizationEngine` built in `axiam-server/src/boot.rs` (not in the
> file list; needed to wire it) through two trait objects,
> `UserServiceAuthorizer` and `CredentialAuditSink`; no new crate edge, no proto
> change. Tests: `grpc_auth_test` 4 new failing-before (another user's record,
> user token, unpermitted service account, audit rows), `grpc_units`
> `get_user_of_another_user_without_users_get_is_denied` (was the pinned-defect
> case) and a rewritten `get_user_success` (self-read), `seeder_default_data_test`
> `users_validate_credentials_is_granted_to_no_default_role`; all failed before
> and pass after. After: `grpc_auth_test` 15, `grpc_server_test` 7, `grpc_units`
> 55, seeder 22, REST `m2m_management_test` 16, `rbac_test` 12; workspace clippy,
> fmt, layering, digest and registry checks clean.
> **Upgrade note for SA-50:** gRPC `GetUser` of another user needs `users:get`;
> `ValidateCredentials` accepts only a service account granted
> `users:validate_credentials`, which no role holds after upgrade, so existing
> SDK gRPC callers get `PERMISSION_DENIED` until an operator grants it.

- **Model:** Opus 5.5. Adds a permission to the registry and wires the
  authorization engine into a service that has none.
- **Files:** `crates/axiam-api-grpc/src/services/user.rs` (138, 180, 272–275),
  `crates/axiam-api-grpc/src/server.rs`, `crates/axiam-api-rest/src/permissions.rs`
  (registry), `crates/axiam-db/src/seeder.rs`, `crates/axiam-api-grpc/tests/`.

Instructions: validate (a token whose subject holds no grants reads another
user's record). Inject the `AuthorizationEngine`. `GetUser`: allow when
`claims.sub == request.user_id`, otherwise require `users:get`.
`ValidateCredentials`: require an `axiam:m2m` principal holding the new
`users:validate_credentials`; seed it to no role by default. Write an
`auth.credentials_validated` audit row for success and failure. Respect the
crate layering check (`scripts/check-crate-layering.py`). Rewrite
`get_user_success`. Record the behaviour change for SA-50's upgrade notes: SDK
gRPC callers of these RPCs now need the permission.

### SA-13 — Enforce tenant suspension (N16, D-3)

> **EXECUTED (2026-11-21, Opus 5.5). N16: reproduced.** A `suspended` tenant
> kept issuing and accepting credentials: password login, refresh, OAuth2
> token grants, token exchange, device authorization, WebAuthn, OIDC/social
> first-time SSO, handoff redemption, SCIM bearer tokens, the REST extractor,
> gRPC and AMQP authz all answered as for an active tenant, and existing
> sessions survived the status change. The fix adds
> `axiam_core::tenant_accepts_principals` and a `TenantAdmission` port, and
> checks it at every door: `create_session_and_tokens` and `refresh`
> (`axiam-auth`), `live_tenant` and token exchange (`axiam-oauth2`), login and
> device auth, the REST auth extractor (`TenantScopeResolver::admit_principals`),
> the SCIM token resolver, a new gRPC `tenant_admission` layer (fails **closed**
> with `UNAVAILABLE` on a datastore error) and the AMQP `authz_consumer`.
> Suspending a tenant deletes its sessions and revokes its refresh tokens in
> the same transaction as the status write; the tombstone also revokes SCIM
> tokens. New error `AxiamError::TenantSuspended` → REST 403 / OAuth2 400 /
> gRPC `PERMISSION_DENIED` / AMQP `reason_code`, all `tenant_suspended`.
>
> Owner decisions taken during execution (binding):
> - **OD-13a** — the Organization-kind tenant cannot be suspended: 409
>   `organization_tenant_not_suspendable` (`AxiamError::OrganizationTenantNotSuspendable`),
>   checked in the handler before any revocation and again in
>   `SurrealTenantRepository::update`.
> - **OD-13b** — on a suspended tenant, organization principals acting through
>   the `X-Axiam-Tenant` header get reads and the status change only; any other
>   write, including a tenant update that also changes name, slug or metadata,
>   returns 403 `tenant_suspended`.
> - **OD-13c** — path-scoped organization routes block writes and allow reads:
>   signing-CA creation and `sign-csr` are refused, intermediate listing,
>   tenant `GET`, `audit-export` and tenant `DELETE` stay allowed. Header-scoped
>   read-only POSTs (`/authz/check`, `/authz/check/batch`, audit export,
>   `saml/parse-sp-metadata`, `/pgp-keys/{id}/encrypt`, `/oauth2/userinfo`)
>   count as reads; `email-config/test` and `/account/export` stay writes.
>   Recorded in `docs/admin/organization-scope.md`, "Suspending a tenant".
>
> Tests: new `tenant_suspension_test` (15), plus additions to
> `auth_service_test`, `webauthn_single_use_test`, `device_auth_test`,
> `opaque_login_test`, `federation_first_time_sso_test`,
> `federation_login_providers_test`, `authz_consumer_test` and the gRPC
> admission layer; each failed before and passes after. Regression: REST lib
> 333, `tenant_test` 30, `org_scope_gaps` 11, `tenant_scoped_roles` 15,
> `tenant_issuer_paths` 22, `organization_scope_consistency` 8,
> `certificate_test` 17, `auth_test` 33, `oauth2_flow_test` 49. fmt, layering,
> spec digest, registry and workspace clippy clean. No OpenAPI-visible change.
>
> **Upgrade notes (SA-50):** suspending a tenant now ends its sessions and
> refresh tokens immediately and is not undone by reactivation; the
> organization's own tenant can no longer be suspended; clients must handle
> `tenant_suspended` (and SA-17 carries both codes into CONTRACT.md).

- **Model:** Opus 5.5. Every authentication door has to agree.
- **Files:** `crates/axiam-db/src/repository/tenant.rs` (status update,
  tombstone transaction 1132–1167), `crates/axiam-auth/src/service.rs` (login),
  `crates/axiam-oauth2` (token, refresh, client credentials),
  `crates/axiam-api-rest/src/extractors/` (principal and `scim_token.rs`),
  `handlers/auth.rs` (`device_auth`), `crates/axiam-api-grpc/src/middleware/auth.rs`.

Instructions:

1. Validate: suspend tenant T, then log in as U and call an API with a
   pre-suspension token; both succeed today.
2. Add one predicate, `tenant_accepts_principals(tenant)`, in `axiam-core` and
   use it at every door: password, OPAQUE, WebAuthn, federation and social
   login; the token endpoint for every grant; refresh; device mTLS; SCIM token
   resolution; the REST principal extractor; the gRPC interceptor; AMQP authz
   requests. Refuse with a stable `tenant_suspended` error.
3. Do not add a database read per request where the tenant is already loaded.
   Where it is not, reuse the existing tenant cache if there is one and state
   the staleness bound; otherwise load it and measure nothing — correctness
   first.
4. On the transition to `Suspended`, revoke sessions and refresh tokens in the
   same transaction, as the tombstone does.
5. Organization principals keep read access and can set the status back.
6. Same transaction as the tombstone: add
   `UPDATE scim_token SET revoked_at = time::now() WHERE tenant_id = $id AND revoked_at = NONE`,
   and make `SurrealScimTokenResolver::resolve` refuse a tombstoned or suspended
   tenant.

Tests: one per door, plus un-suspend restores sign-in (new session required).

### SA-14 — Signed envelope on mail and outbound queues (N3)

> **EXECUTED (2026-11-21, Opus 5.5). N3: reproduced.** An unsigned message on
> the mail queue with a nil `user_id` was mailed, tenant-branded, to the
> `to_address` and link the publisher chose; an unsigned SSF-push or webhook
> message on the outbound queues reached its deliverer; and `deliver_once`
> POSTed to a disabled webhook and for an event it did not subscribe to.
> The fix adds `axiam_amqp::internal_envelope`: `InternalEnvelope`
> (`purpose`, `key_version`, `nonce`, `issued_at`, `body`, `hmac_signature`)
> sealed with a **server-only** key derived by HKDF-SHA256 from the AMQP master
> key under `info = "axiam-amqp-internal-v1" || key_version || purpose`, so no
> tenant subkey can sign it and a key is bound to one queue family.
> `InternalQueueGate::open` checks shape, signature presence, purpose, HMAC,
> key version, freshness (`replay_skew`) and the durable nonce store; every
> refusal is nacked to the DLQ and writes an `amqp.internal_message_rejected`
> row to the nil-tenant system audit log (metadata `{queue, reason}` only).
> Mail, webhook and outbound publishers seal; the mail, webhook and outbound
> consumers open. Retry copies are re-sealed; outbound retries carry
> `issued_at` = TTL expiry so the 1 h backoff is not refused as stale. New
> setting `amqp.internal_queues.require_signature` (default `true`). The
> `to_address` fallback is removed for non-Notification mail (an unresolvable
> user sends nothing), and `deliver_once` refuses disabled webhooks and
> unsubscribed events as terminal (dead-letter, no retry).
>
> Tests: `sa14_unsigned_outbound_messages_never_reach_the_deliverer` (lib),
> `sa14_an_unresolvable_user_is_not_mailed_at_the_messages_address`,
> `sa14_a_disabled_webhook_is_not_delivered_to`,
> `sa14_an_unsubscribed_event_is_not_delivered` failed before and pass after;
> plus envelope unit and integration tests (replay, unsigned, foreign/tenant
> key, stale, flag off). The report's SSF test was moved from the oauth2
> deliverer to the consumer seam, where the guard sits (layering forbids
> `axiam-amqp` → `axiam-oauth2`). §1.2 rewrites:
> `user_lookup_failure_falls_back_to_advisory_address` →
> `user_lookup_failure_sends_nothing`; mail consumer/template/in-process tests
> now seed a real user. Regression: `axiam-amqp` all green (lib 210), REST lib
> 333, `webhook_test` 28, `webhook_outbound_test` 6,
> `outbound_supervisor_single_copy` 5. fmt, layering, digest, registry and
> workspace clippy clean. No OpenAPI change; AsyncAPI documents the envelope.
>
> **Upgrade notes (SA-50):** old replicas cannot read the new envelope, so
> roll producers and consumers together; drain the mail, webhook and outbound
> queues before upgrading, or set `require_signature = false` for one
> deployment. Messages already in a DLQ are in the old shape and replay only
> with the flag off; a message dead-lettered after the upgrade is refused as
> stale if replayed more than `REPLAY_SKEW_SECS` after it was published.
> Mail to an unknown user and deliveries to disabled or unsubscribed webhooks
> are no longer sent.

- **Model:** Opus 5.5. New wire envelope, producer and consumer must roll over
  together.
- **Files:** `crates/axiam-amqp/src/mail_consumer.rs` (508),
  `crates/axiam-amqp/src/outbound/wire.rs` (59), their producers, the existing
  HMAC/nonce/freshness envelope used by the authz and audit queues.

Instructions: validate with the two tests in the report. Reuse the existing
envelope (HMAC, nonce, `issued_at`, replay store) with a **server-only** key
derived under a distinct HKDF label — these queues have no SDK producer, so the
tenant subkey must not be able to sign them. Consumers reject unsigned, stale
and replayed messages and write an audit row. Rolling upgrade: add
`amqp.internal_queues.require_signature` (default `true`); the upgrade notes
tell operators to drain the queues or set it to `false` for one deployment.
Also, as the report asks: drop the `to_address` fallback for non-Notification
mail types, and make `deliver_once` check `webhook.enabled` and the event
subscription.

### SA-15 — Signed, per-producer authz responses (N2)

> **EXECUTED (2026-11-21, Opus 5.5). N2: reproduced.** On the unfixed code
> `process_authz_request` answered two tenants with responses carrying only
> `correlation_id`, `allowed`, `reason` and `reason_code` — no tenant, no nonce,
> no signature — and the consumer always published to the shared
> `axiam.authz.response` queue, ignoring `reply_to`. The fix is additive:
> `AuthzResponse` gains `tenant_id`, the request `nonce` and `hmac_signature`
> (HMAC-SHA256 with the request's tenant subkey at the request's
> `key_version`, via the existing `derive_tenant_key`) over the canonical form:
> compact JSON without `hmac_signature`, members in the order
> `correlation_id, allowed, reason?, reason_code?, tenant_id, nonce`, optional
> members omitted when absent. Every response path (allow/deny, engine error,
> `tenant_suspended`, tenant-read error) is signed. A non-empty AMQP
> `reply_to` routes the response there on the default exchange; otherwise it
> goes to the shared queue as before (`response_routing_key`). The response
> carries no `key_version`; the requester verifies with the one it sent.
>
> Tests: `n2_responses_for_two_tenants_are_tenant_bound_and_signed` and
> `n2_the_tenant_suspended_denial_is_signed` failed before (no `tenant_id`) and
> pass after; `authz_response_routing_test` (2) did not compile before (no
> routing seam) and passes after; `authz_response_vectors` pins the subkey and
> three vectors (allow, deny `no_grant`, deny `denied_by_rule`) byte for byte,
> answering the existing `AuthzRequest` vector, cross-checked by an independent
> Python HKDF/HMAC computation. Regression: `axiam-amqp` all green (lib 210,
> `authz_consumer_test` 13, v2 reference vectors 2). fmt, all Architecture
> Invariants checks and workspace clippy clean. AsyncAPI documents the new
> fields, routing and canonical form (and the already-sent `reason_code`).
> CONTRACT §8 text and vectors are handed to SA-17.
>
> **Upgrade notes (SA-50):** additive on the wire; existing consumers that
> ignore unknown fields are unaffected. SDKs gain response verification in
> Wave 3 (D-9). A requester that sets `reply_to` now receives its response on
> that queue instead of the shared one.

- **Model:** Opus 5.5. Changes CONTRACT §8.
- **Files:** `crates/axiam-amqp/src/authz_consumer.rs` (304),
  `crates/axiam-amqp/src/messages.rs` (202), `sdks/CONTRACT.md` §8.

Instructions: validate with the broker-free harness in the report. Make the
change **additive**: `AuthzResponse` gains `tenant_id`, the request `nonce` and
`hmac_signature` computed with the tenant subkey over the canonical response;
when the request carries AMQP `reply_to` the response goes there, otherwise to
the shared queue as today. Produce the canonical form of the signed response
and at least two test vectors (allow and deny) for SA-17 to put in CONTRACT §8;
the seven AMQP SDKs verify against them in Wave 3 (D-9).

### SA-16 — Supply chain and deployment (N17, N18, N19)

- **Model:** Sonnet 5.5.
- **Files:** `.github/workflows/release-opaque.yml`, `docker/docker-compose.dev.yml`
  (68, 111, 143), `docker/docker-compose.prod.yml` (133, 178, 419),
  `docker/docker-compose.minimal.yml` (72), `k8s/surrealdb/statefulset.yml` (42–43).

Instructions:

1. N17: pin every `uses:` in `release-opaque.yml` to a 40-character commit SHA
   with the version in a trailing comment. Reuse the SHAs `release.yml` already
   pins for the same actions; resolve the rest with `git ls-remote`. Replace
   `npm@latest` with an exact version. Acceptance:
   `grep -nE 'uses: [^ ]+@' .github/workflows/release-opaque.yml | grep -vE '@[0-9a-f]{40}'`
   prints nothing.
2. N18: use the image name `release.yml` publishes and a released version tag.
3. N19: pass SurrealDB credentials through `SURREAL_USER` / `SURREAL_PASS`
   (from the existing secret or env file) and remove `--user` / `--pass` from
   every command line, health checks included. Verify with
   `docker compose … config` that no password remains in a `command:`.

### SA-18 — `roles` scope and claim (N15, D-1)

- **Model:** Opus 5.5. New token content, touched by every grant.
- **Depends on:** SA-03.
- **Files:** `crates/axiam-oauth2` (scope handling, token minting for every
  grant, discovery metadata), `crates/axiam-auth/src/token.rs` (claims),
  `crates/axiam-authz` or the role repository (global-role lookup), the DCR and
  client-management scope validation, `sdks/openapi.json` if a type changes.

Instructions:

1. Add a standard scope named `roles`. A client obtains it only if it is in the
   client's allowed scopes, exactly like any other scope; nothing is granted by
   default to existing clients.
2. When the granted scope set contains `roles`, the access token carries
   `roles`: a JSON array of the **names** of the subject's global roles in the
   token's tenant — assigned directly or inherited through groups — at mint
   time. Resource-specific role assignments are **not** included. Sort and
   de-duplicate the array.
3. Applies to user tokens and to service-account tokens. On refresh the claim is
   recomputed. On token exchange it survives only if `roles` survives scope
   narrowing. Never add it to ID tokens or to userinfo.
4. Without the scope the claim is absent — not an empty array — so that SDKs
   can tell "not requested" from "no roles".
5. Advertise the scope in `scopes_supported` and the claim in
   `claims_supported`. Document in `docs/` that the claim is a snapshot, stale
   for at most one access-token lifetime, and that `require_access` remains the
   authoritative check.

Tests: scope absent → no claim; scope granted → exact role names, group
inheritance included, resource-specific roles excluded; client not allowed the
scope → request refused as for any unallowed scope; refresh after a role change
reflects it; exchange with narrowed scope drops it.

### SA-17 — CONTRACT 1.66

- **Model:** Opus 5.5. Eleven SDK tasks implement exactly what this says.
- **Depends on:** SA-03, SA-15, SA-18. Runs last in Wave 2.
- **Files:** `sdks/CONTRACT.md` (§3a, §10, §11, §12, §12.4, change log).

Write normative text for:

1. **§12 login glue — browser binding (C7).** At login the glue generates 32
   random bytes, sets them as cookie `__Host-axiam_oidc_bind`
   (`HttpOnly; Secure; SameSite=Lax; Path=/`) and stores their SHA-256 on the
   state entry. At the callback it consumes the entry first (state stays
   single-use), then compares digests in constant time; missing or different →
   the uniform 401, no code exchange, no success callback. The cookie is cleared
   on both outcomes. State the non-`__Host-` fallback name for plain-HTTP
   loopback development. The state-store interface gains an optional binding
   field. The success callback receives the request.
2. **§12 login glue — `return_to` (C6).** Accepted only when it starts with a
   single `/`, does not start with `//` or `/\`, and contains no backslash or
   control character; validated when stored and again before redirecting;
   otherwise dropped. An integrator-supplied predicate MAY widen it.
3. **§12.4 rule 2 (C5).** Already normative; add the conformance test: 50
   unknown `kid`s in one 60 s window cause at most one fetch.
4. **§10 access-token verification (N14).** Reject a token whose claims contain
   `purpose`; reject when header `typ` is present and is not `at+jwt`; require
   `kid` on the access-token path (no single-key fallback).
5. **§11 `require_role` (N15, D-1).** Reads the `roles` claim only; never
   derived from `scope`; absent claim → 403. New `require_scope(scope...)`
   helper. Specify the `roles` scope and claim exactly as SA-18 implements
   them, and that an application wanting `require_role` must request the scope.
7. **§8 signed authz response (N2).** The response fields, the canonical form
   and the test vectors from SA-15. A consumer MUST verify the signature with
   the tenant subkey, MUST check that `nonce` and `tenant_id` match its own
   request, and MUST discard a response that fails either check. State the
   behaviour against a server older than 1.66 (no signature): accepted only
   when the integrator sets an explicit opt-out, refused by default.
6. **§3a (N12).** Restate that the inbound double-submit check applies to every
   guard that accepts a cookie credential.

Bump the contract version, add the change-log entry, and list the SDKs each
clause obliges.

---

## 6. Wave 3 — SDKs

Common instructions for SA-20 … SA-30:

- Start by re-syncing the vendored `CONTRACT.md` (and `openapi.json`, `proto/`
  if changed) from `ilpanich/axiam` after SA-17, the way the repository's drift
  check expects.
- Use the repository's own build, lint and test commands. Add an entry to its
  changelog; C7, C6 and N15 are **behaviour changes** for integrators and need a
  minor version bump and a migration note.
- **N14 in every SDK:** apply CONTRACT §10 as amended. Tests: a token with a
  `purpose` claim is refused; a token with header `typ: axiam-webauthn-state+jwt`
  is refused; a `kid`-less token is refused on the access-token path; a normal
  token passes.
- **N15 where listed:** remove the scope-to-role mapping, read `roles` only,
  add `require_scope`. Tests: scope `openid admin` with no `roles` → 403 on
  `require_role("admin")`; `roles: ["admin"]` → 200; `require_scope("admin")`
  → 200 for the first token. Document that the application must request the
  `roles` scope (SA-18) for `require_role` to work.
- **N2 where listed** (Rust, TypeScript, Python, Java, C#, PHP, Go): verify the
  signed authz response per CONTRACT §8 as amended — signature with the tenant
  subkey, `nonce` and `tenant_id` equal to the request's — and publish requests
  with a private `reply_to` queue. Tests: both contract test vectors verify; a
  tampered decision, a response for another nonce and a response for another
  tenant are each discarded; an unsigned response is refused unless the opt-out
  is set. Take care not to repeat C2: verify and deliver the **same** bytes.

### SA-20 — TypeScript SDK (reference) — Opus 5.5

`src/middleware/oidcLoginCore.ts` (143, 197, 227), `src/node/oidcState.ts` (115),
`src/middleware/express.ts` (350–359), `src/middleware/fastify.ts` (~357),
`src/middleware/verifyCore.ts` (195), `src/node/jwks.ts`.

1. C7: implement the binding. The core is framework-free, so it takes the cookie
   value as a parameter and returns the cookie to set; the Express and Fastify
   adapters read and write it. Extend the `OidcStateStore` interface with the
   optional binding digest without breaking custom stores.
2. C6: validate `returnTo` in both adapters with one shared function and expose
   the optional predicate.
3. N2, N14, N15 as above.
4. Ride-along, same files: reject a non-finite clock skew
   (`node/oidcIdToken.ts`); cap `MemoryOidcStateStore`; compare origin, not
   host, in `rest/session.ts:276`.
5. Write `docs/login-glue-binding.md` in this repository describing the design
   decisions (cookie name and fallback, order of consume and compare, store
   interface). SA-21…SA-25 port from it.

Tests: callback with valid state and no cookie → 401 and `onSuccess` not called;
with another browser's cookie → 401; with the right cookie → success; state is
consumed in all three cases; absolute, scheme-relative and backslash `returnTo`
produce no redirect to that target.

### SA-21 — Python SDK — Sonnet 5.5

`src/axiam_sdk/django/oidc.py` (101, 118, 196, 198), the FastAPI/Flask login
glue if present, `src/axiam_sdk/fastapi/__init__.py` (299). Port C7 and C6 from
SA-20 (`_safe_return_to` as sketched in the report), N2, N14, N15. Ride-along:
`hmac.compare_digest` on encoded bytes (`fastapi/__init__.py:225`,
`django/middleware.py:136`); cap the in-memory state store.

### SA-22 — PHP SDK — Sonnet 5.5

`src/Auth/JwksVerifier.php` (253, 704, 714), `src/Oidc/OidcLoginFlow.php`,
`src/AccessEnforcer.php` (166), `src/Laravel/AxiamMiddleware.php` (170, 252),
`src/Symfony/AxiamAuthSubscriber.php` (272).

1. C5: record the time of the last refetch caused by an unknown `kid`; within
   60 s, while the cache is otherwise fresh, reject from cache. Cache the
   resolved `jwks_uri`. Test: 50 random kids → at most one fetch; a rotated key
   is accepted after the window.
2. C6, C7 ported from SA-20; N2; N14; N15.
3. Ride-along: `AxiamAccessMiddleware` attribute mode must **deny** when the
   route action cannot be reflected.

### SA-23 — C# SDK — Sonnet 5.5

`Axiam.Sdk/Auth/JwksVerifier.cs` (808), `Axiam.Sdk.AspNetCore/OidcLoginEndpoints.cs`.
C5 (cooldown term in `IsFresh`, same test as PHP); C6 with `Url.IsLocalUrl`
semantics; C7 ported from SA-20; N2; N14; N15 (document the framework-native
`[Authorize(Roles = …)]` mapping reads the `roles` claim only). Ride-along: reject an empty expected nonce
in `OidcExchangeAsync`; clamp `JwksCacheTtl`.

### SA-24 — Java SDK — Sonnet 5.5

`spring/AxiamAuthenticationFilter.java` (200, 224, 267),
`spring/AxiamAuthorizationInterceptor.java` (358), `annotations/AxiamRequireRole.java`,
`internal/JwksVerifier.java` (965–1000), the OIDC login glue, the AMQP consumer.

1. C7 ported from SA-20; N2; N14 (this also closes the `kid`-less acceptance in
   `selectKey`); N15, including the Spring authorities: prefix scopes with
   `SCOPE_` so a scope named `ROLE_X` cannot satisfy `hasRole("X")`.
2. **C2 parity check:** port the Go regression test (a body with forged
   lower-case keys followed by the signed values under case-variant keys). If
   the handler sees unsigned values, fix it the way SA-26 does; if not, keep the
   test and record "not affected".
3. Unknown-`kid` cooldown: write the C5 test. If more than one fetch occurs, add
   an explicit per-verifier cooldown; do not rely on `DefaultJWKSetCache`.

### SA-25 — Kotlin SDK — Sonnet 5.5

`ktor/AxiamAuthentication.kt` (50, 107, 177, 205–206, 270), `AxiamOidcLogin.kt`
(81, 215, 224), `AxiamClient.kt` (1511), `Models.kt`.

1. N12: validate with the Ktor `testApplication` case in the report, then apply
   §3a when the credential came from the `axiam_access` cookie and the method is
   POST, PUT, PATCH or DELETE: `X-CSRF-Token` must equal the `axiam_csrf`
   cookie, compared in constant time, else 403.
2. C6, C7 ported from SA-20; N14; N15; the unknown-`kid` cooldown test as in SA-24.

### SA-26 — Go SDK — Sonnet 5.5

`amqp/consumer.go` (152, 178), `amqp/hmac.go` (157–189), `amqp/event.go` (24–31),
`examples/amqp-consumer/main.go`.

1. C2: `verifyHMAC` returns the matched canonical bytes; `parseEvent` builds
   `Event.Fields` and `Event.Raw` from those bytes, never from the raw body.
   Additionally nack any body containing duplicate keys or keys that differ only
   by case. Regression test: the forged body is nacked and the handler is never
   called; the plain-tamper control still nacks; a legitimate message still
   dispatches.
2. N2; N14; N15 (`middleware.RequireRole`).

### SA-27 — Rust SDK — Sonnet 5.5

`src/token/jwks.rs` (552, 1126, 1158, 1391), `src/middleware/actix.rs` (451).
Validate N14 with the report's test (kid-less `mfa_challenge` token accepted
with only `expect_tenant_id`), then apply §10: `purpose` rejected, `typ`
checked, no single-key fallback in `find_jwk` on the access-token path. N2. N15.
Ride-along: checked arithmetic at `dpop.rs:417`.

### SA-28 — C++ SDK — Sonnet 5.5

`src/jwks.cpp` (118–123, 184–192), `src/authenticator.cpp` (133, 246–249),
`include/axiam/authenticator.hpp` (186), `src/oidc.cpp` (1047, 1696).

C4: require `header.is_object()`; read `alg` and `kid` with `find()` plus
`is_string()`; in `load_from_json` skip members whose `kty`, `crv`, `kid` or `x`
are not strings; catch `nlohmann::json::exception` in `verify_with_reason`
(→ `kInvalidAlg`) and `std::exception` in `try_authenticate` (→ `nullopt`).
Tests: the four hostile headers from the report return `nullopt` /
`kInvalidAlg`; `{"keys":[{"kty":1}]}` yields zero keys without throwing. N14.
Ride-along: reject a password with an embedded NUL in `src/opaque.cpp`.

### SA-29 — C SDK — Sonnet 5.5

N14 only. Ride-along: cap the response body in `src/transport_curl.c` `write_cb`;
range-check doubles before the integer casts at `src/client.c:921` and
`reactor.c:245`.

### SA-30 — Swift SDK — Sonnet 5.5

N14 only.

---

## 7. Wave 4 — hardening, and what is left out

### SA-40 — REST edge matchers — Sonnet 5.5

`normalize_for_public_check`: reject any segment that percent-decodes to `.` or
`..`. `is_csrf_exempt`: exact equality on the scope-relative path instead of
`ends_with`. `tenant_path` duplicate-selector check: compare percent-decoded
keys via `url::form_urlencoded::parse`. One test per bypass form quoted in the
report.

### SA-41 — OAuth2 — Sonnet 5.5

`token.rs:2488`: reject a `code_verifier` when the code has no stored challenge.
`par.rs:328–345`: check the presenting client before consuming the
`request_uri`. `token.rs:3655–3715` and gRPC `IntrospectToken`: report
`active: false` when the token's `sid` session is no longer live.

### SA-42 — SSRF guard — Sonnet 5.5

`ssrf.rs:210–211`: apply `is_never_allowed` to every resolved address even when
`allow_private` is true. `dcr.rs:349` `host_glob_matches`: compare byte slices,
no panic on non-ASCII. `ip_class.rs` `classify_v6`: classify `::ffff:0:0/96` as
special-purpose.

### SA-43 — MFA and WebAuthn — Opus 5.5

`service.rs:1051` `enroll_mfa`: write the pending secret to a separate field and
swap it in at `confirm_mfa`, so re-enrolment cannot invalidate a confirmed
authenticator. `enroll_mfa_with_setup_token`: use the same
`available_method_types` guard as the WebAuthn twin and make setup tokens
single-use. `webauthn.rs:1125` `finish_authentication`: call
`ensure_can_sign_in`. `verify_mfa`: add a per-account failure counter that
feeds the existing lockout. Opus because the pending-secret change is a schema
and state-machine change on the MFA path.

### SA-44 — Audit and gRPC — Sonnet 5.5

`axiam-audit/src/middleware.rs:543`: redact the token segment of
`/api/v1/account/export/{token}` (and any other path-borne secret; search for
them). `axiam-api-grpc/src/server.rs:373–377`: set `max_decoding_message_size`
explicitly and correct the comment. `/health/jobs`: return an error category,
not the `Display` of the error. The `ValidateCredentials` audit row belongs to
SA-12; skip it here.

### SA-45 — Deployment manifests — Sonnet 5.5

`automountServiceAccountToken: false` on every pod; a controller `podSelector`
on `allow-ingress-to-server`; dev and e2e compose bind SurrealDB, RabbitMQ and
Vault to `127.0.0.1`; `externalTrafficPolicy: Local` on the rpi5-k3s ServiceLB;
`TRUSTED_PROXIES` documented next to `TRUSTED_HOPS` in the k8s ConfigMap.

### Not planned

| Item | Why |
|---|---|
| The 14 deferred coverage units, the final-clean critic, Phase 5 | Audit work. Re-run the audit after this plan lands. |
| AAD binding for AES-256-GCM secrets | Requires re-encrypting every stored secret; needs a migration design. |
| Privilege ceiling on `roles:assign`, `groups:add_member`, `permissions:grant` | Documented accepted risk (`threat-model-stride.md:429`, `:4777`); a "delegate only what you hold" rule is a feature. |
| gRPC strict revocation off by default; refresh outliving session expiry | Documented accepted postures (#844). |
| Authenticated `/federation/saml/acs` and `/federation/oidc/callback` linking nothing | Bind-or-remove is an API decision for the owner. |
| OIDC federation ignoring `email_verified` | Changes provisioning for existing IdPs; needs an owner decision. |
| Global uniqueness of SSF stream audience | By design (D-47). |
| Tenant-less certificate repository signatures; unique index on `cert_bound_to` | No boundary crossing; refactor. |
| Master-key rotation for AMQP subkeys; webhook secret minimum length; OPAQUE client memory ceiling | Each changes an operator-facing contract; batch into a crypto-policy change. |
| `http://` base URLs accepted by several SDKs; default expected audience in guards | Not contract requirements today; decide once in CONTRACT, then fan out. |
| Functional notes (relative mail links, CSP `form-action` vs. SAML POST, UMA list paging, consent page client name, deletion cancel as GET) | Not security defects; file as issues. |
| Mutable base-image tags | Digest pinning needs registry access and a renewal process (Dependabot/Renovate). |

---

## 8. Wave 5 — close-out

### SA-50 — Documentation and regression gate — Sonnet 5.5

1. `claude_dev/threat-model-stride.md`: add or update one entry per fixed
   finding, with the control and the test that pins it; update the counts.
2. Upgrade notes for the next release: SA-01 (bootstrap now needs the token),
   SA-02 (permissions withheld from Standard tenants), SA-03 (`typ`,
   `allow_missing_aud_as_user`), SA-18 (new `roles` scope; `require_role` in
   the SDKs now needs it), SA-12 (gRPC permissions), SA-13 (suspension is
   enforced), SA-11 (SAML audience required), SA-14 (queue drain), SA-10 (no
   egress proxy for guarded fetches).
3. `docs/admin/`: bootstrap, tenant suspension, AMQP internal queue signing.
4. Final gate, once: `just check` on the whole workspace (the one place an
   unscoped build is justified), `python3 scripts/check-spec-digest.py`,
   `python3 scripts/check-crate-layering.py`, and the `sdks/openapi.json` drift
   check.
5. Set this document's status line to `EXECUTED`, with the list of leads that
   did not reproduce and the outcome of the five review gates.
