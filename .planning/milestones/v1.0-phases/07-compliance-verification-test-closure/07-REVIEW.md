---
phase: 07-compliance-verification-test-closure
reviewed: 2026-06-07T00:00:00Z
depth: standard
files_reviewed: 28
files_reviewed_list:
  - crates/axiam-api-rest/src/handlers/oauth2.rs
  - crates/axiam-api-grpc/build.rs
  - crates/axiam-api-grpc/Cargo.toml
  - crates/axiam-api-grpc/tests/grpc_authz_test.rs
  - crates/axiam-api-rest/tests/oauth2_conformance.rs
  - crates/axiam-api-rest/tests/oidc_conformance.rs
  - crates/axiam-pki/Cargo.toml
  - crates/axiam-pki/tests/ca_test.rs
  - crates/axiam-pki/tests/cert_test.rs
  - crates/axiam-pki/tests/mtls_test.rs
  - crates/axiam-pki/tests/pgp_test.rs
  - docker/docker-compose.e2e.yml
  - frontend/e2e/helpers/auth.ts
  - frontend/e2e/login.spec.ts
  - frontend/e2e/federation.spec.ts
  - frontend/e2e/certificates.spec.ts
  - frontend/e2e/dashboard.spec.ts
  - frontend/e2e/identity.spec.ts
  - frontend/e2e/organizations.spec.ts
  - frontend/e2e/roles.spec.ts
  - frontend/e2e/service-accounts.spec.ts
  - frontend/e2e/settings.spec.ts
  - frontend/e2e/tenants.spec.ts
  - frontend/e2e/users.spec.ts
  - frontend/playwright.config.ts
  - .github/workflows/ci.yml
  - scripts/e2e-bootstrap.sh
findings:
  critical: 1
  warning: 6
  info: 5
  total: 12
status: issues_found
---

# Phase 7: Code Review Report

**Reviewed:** 2026-06-07
**Depth:** standard
**Files Reviewed:** 28
**Status:** issues_found

## Summary

Reviewed the compliance/test-closure phase. The one production change
(`oauth2.rs` WWW-Authenticate fix) is **correct** — the 401-only header guard
is sound, no header injection (static value), and no regression to the redirect
/ 400 / 500 paths. The bug count is concentrated in the new test infrastructure.

The headline defect is a **SurrealQL syntax error in `e2e-bootstrap.sh`**:
it calls `type:record(...)` (single colon) instead of the `type::record(...)`
(double colon) function used everywhere else in the codebase. Combined with
`curl -sf` not catching SurrealDB per-statement errors (the `/sql` endpoint
returns HTTP 200 even on statement failure), the org+tenant seed silently fails
and the whole E2E suite runs against a half-bootstrapped DB — false-red at best,
and exactly the false-green class the compose comments claim to defend against.

Secondary concerns: several frontend assertions are tautological
(`expect(... || true).toBe(true)`), the e2e job has no concurrency cancel,
and credentials are duplicated across script/compose/workflow.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: SurrealQL `type:record` (single colon) — org/tenant seed never executes

**File:** `scripts/e2e-bootstrap.sh:71,78`
**Issue:** The seed SQL uses `CREATE type:record('organization', '${ORG_ID}')`
and `CREATE type:record('tenant', '${TENANT_ID}')` with a **single** colon.
The correct SurrealQL function is `type::record(...)` (double colon) — this is
what every other call site uses (`crates/axiam-db/src/seeder.rs:49`,
`crates/axiam-db/src/repository/notification_rule.rs:127`, and the project
MEMORY note "use `type::record('table', $id)`"). `type:record` parses as the
record-id literal `type:record` followed by `(...)`, which is a syntax error.

The failure is silent: SurrealDB's HTTP `/sql` endpoint returns **HTTP 200**
with a per-statement error in the JSON body. `curl -sf` (line 63) only fails on
HTTP-level errors, so the `|| { ...; exit 1; }` guard at lines 86–89 never
fires. The script prints "Org and tenant created." (line 91) and proceeds.
The subsequent `/admin/bootstrap` call (which references the never-created
`org_id`/`tenant_id`) then fails or produces a dangling user, breaking every
downstream E2E test. This is the precise false-result failure mode the compose
file warns about (W8).
**Fix:**
```bash
CREATE type::record('organization', '${ORG_ID}') SET
  ...
CREATE type::record('tenant', '${TENANT_ID}') SET
  ...
```
Additionally, make the failure non-silent — parse the response for per-statement
errors instead of relying on `curl -f`:
```bash
if echo "${SURREAL_RESPONSE}" | grep -q '"status":"ERR"'; then
  echo "[e2e-bootstrap] ERROR: SurrealDB statement failed: ${SURREAL_RESPONSE}"
  exit 1
fi
```

## Warnings

### WR-01: SurrealQL/JSON injection via unescaped env-var interpolation in seed

**File:** `scripts/e2e-bootstrap.sh:70-89,101-110`
**Issue:** `${ORG_SLUG}`, `${TENANT_SLUG}`, `${ADMIN_EMAIL}`, `${ADMIN_PASSWORD}`
are interpolated raw into the SurrealQL string and into the JSON bootstrap body.
A value containing a single quote breaks the SurrealQL (`slug = '${ORG_SLUG}'`)
and a value with `"`/newline/backslash breaks the JSON heredoc — producing
malformed requests or SurrealQL injection. Test-only, so not a production
vulnerability, but it makes the bootstrap brittle and silently mis-seed if
anyone overrides the defaults (e.g. a password with a quote). Defaults today
are clean, so this won't bite CI immediately — hence WARNING not BLOCKER.
**Fix:** Build the JSON body with a tool that escapes
(`jq -n --arg email "$ADMIN_EMAIL" ... '{...}'`), and validate slugs against
`^[a-z0-9-]+$` before interpolating into SurrealQL. Prefer parameterized
SurrealQL (`$slug` bind vars via the `vars` field) over string interpolation.

### WR-02: Tautological assertions defeat the test's purpose

**File:** `frontend/e2e/users.spec.ts:99,138`; `frontend/e2e/users.spec.ts:135-138`
**Issue:** `expect(hasMfaSection || true).toBe(true)` (users.spec.ts:99) and
`expect(hasGroups || hasEmptyState || true).toBe(true)` (users.spec.ts:138)
can never fail — the `|| true` makes the assertion vacuous. The MFA-section
test and the groups empty-state test therefore assert nothing beyond "the
preceding `await`s did not throw." This is exactly the soft-coverage pattern
this phase is meant to close.
**Fix:** Drop the `|| true` and assert the real condition, e.g.
`expect(hasGroups || hasEmptyState).toBe(true)`, and for MFA branch into a real
assertion when `adminLink` is visible rather than swallowing the result.

### WR-03: `webServer.command: npm run dev` conflicts with the CI serve strategy

**File:** `frontend/playwright.config.ts:20-24` vs `.github/workflows/ci.yml:248-259`
**Issue:** The Playwright config declares a `webServer` that runs `npm run dev`
on port 5173 with `reuseExistingServer: !CI`. In CI, `reuseExistingServer` is
`false`, so Playwright will try to **start its own `npm run dev`** even though
the workflow already serves the production build (`npx serve dist -l 5173`) on
the same port. Two servers contending for 5173 → Playwright's webServer launch
can fail or bind-error, or it shadows the prod build the job intended to test
(testing the dev server, not `dist/`). At minimum it's a port race; at worst the
E2E job validates the wrong artifact.
**Fix:** Gate the `webServer` block off in CI (e.g. `webServer: process.env.CI
? undefined : { ... }`) since the workflow provides the server, or set
`reuseExistingServer: true` unconditionally and ensure the workflow's `serve`
is up before `npm test`.

### WR-04: E2E job lacks concurrency cancellation and `npm run dev` server is never used as intended

**File:** `.github/workflows/ci.yml:205-277`
**Issue:** (a) No `concurrency:` group on the workflow — repeated pushes to a PR
stack full E2E + docker-build runs (each `timeout-minutes: 15`), wasting runners
and racing on fixed host ports 8000/8090/5672. (b) The `serve dist` background
process readiness loop (lines 255–257) `break`s on first success but never fails
the step if `serve` never comes up — `npm test` then runs against a dead URL and
the failure is attributed to the tests, not the missing server.
**Fix:** Add a top-level `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`.
After the readiness loop, assert the server is up:
`curl -sf http://localhost:5173 > /dev/null || { echo "serve failed"; exit 1; }`.

### WR-05: Cookie-based auth helper has no logout/state isolation between parallel workers

**File:** `frontend/e2e/helpers/auth.ts:14-34`; `frontend/playwright.config.ts:5`
**Issue:** `fullyParallel: true` with `workers: 1` in CI is fine, but locally
(`workers: undefined` → N cores) every test runs `loginAsAdmin` against the
**same** admin account over a shared live backend. Single-use refresh-token
rotation (per CLAUDE.md security standards) plus concurrent logins of the same
user can invalidate each other's sessions, producing flaky local runs. The
helper also never logs out, so server-side session/refresh-token state
accumulates across the suite.
**Fix:** Either pin local runs to `workers: 1` for the live-backend project, or
use Playwright `storageState` to log in once and reuse the cookie, and add an
`afterEach` logout. Document the single-account constraint if intentional.

### WR-06: `mtls_rejects_expired_cert` assertion can pass for the wrong reason

**File:** `crates/axiam-pki/tests/mtls_test.rs:277-280`
**Issue:** The reject assertion is
`err_msg.contains("expired") || err_msg.contains("Certificate")`. Because
`mtls.rs` wraps the error as `AxiamError::Certificate(...)`, the Debug string
will contain `"Certificate"` for **any** certificate error — including an
unrelated parse/lookup failure. The test would pass even if the expiry check
were removed, as long as some `Certificate` error is returned. Same weakness in
`mtls_rejects_revoked_cert` (`"not active" || "Certificate"`,
mtls_test.rs:341) and `cert_test.rs:216` (`"expired" || "valid"`).
**Fix:** Assert on the specific message only:
`assert!(err_msg.contains("expired"), ...)` for the expiry test and
`assert!(err_msg.contains("not active"), ...)` for the revoked test. The
`|| "Certificate"` fallback removes the discrimination the reject test exists to
provide.

## Info

### IN-01: Credentials triplicated across script, compose, and workflow

**File:** `scripts/e2e-bootstrap.sh:22`, `docker/docker-compose.e2e.yml:57`, `.github/workflows/ci.yml:225,266`
**Issue:** `Test@Admin123!` / `admin@axiam.dev` are hard-coded in three places.
Drift between them silently breaks bootstrap-vs-login. These are deliberate
test fixtures (acceptable, not a secret leak), but the duplication is a
maintenance hazard.
**Fix:** Define once (workflow `env:` at job level, or a single `.env.e2e`
sourced by both compose and script) and reference everywhere.

### IN-02: `RABBITMQ_DEFAULT_PASS: axiam` and `root:root` SurrealDB creds inline

**File:** `docker/docker-compose.e2e.yml:23,49-50`; `scripts/e2e-bootstrap.sh:69`
**Issue:** Weak/default credentials in the e2e compose and `-u "root:root"` in
the bootstrap curl. Correct for an ephemeral in-memory CI stack, but worth an
explicit "E2E-only" comment next to the RabbitMQ creds (the SurrealDB block and
COOKIE_SECURE already have such guards; RabbitMQ does not).
**Fix:** Add a `# E2E-only — never reuse` comment on the RabbitMQ env block for
parity with the existing COOKIE_SECURE warning.

### IN-03: Deterministic-UUID comment contradicts the code

**File:** `scripts/e2e-bootstrap.sh:58-61`
**Issue:** The comment says "Generate **deterministic** UUIDs ... We use
date-based seeds for reproducibility," but the code reads
`/proc/sys/kernel/random/uuid` (random) with a `uuid.uuid4()` (random) fallback.
Nothing is deterministic or date-seeded. Misleading comment.
**Fix:** Delete the "deterministic / date-based seeds" wording; the UUIDs are
random per-run, which is fine.

### IN-04: `pkce_plain_method_rejected` accepts two outcomes — weak conformance signal

**File:** `crates/axiam-api-rest/tests/oauth2_conformance.rs:355-379`
**Issue:** The test passes whether the server returns a 302 error redirect OR a
400, and accepts either `invalid_request` or `unsupported_challenge_method`.
This is defensible (RFC leaves the surface open) but the broad acceptance means
the test won't catch a behavioral change between the two branches. Acceptable as
a MUST-NOT-issue-code check; noting the reduced precision.
**Fix:** If AXIAM has a fixed policy (it appears to be "reject plain"), pin the
expected status + error code to lock the contract.

### IN-05: `concurrent_check_access` deny-path is over-permissive

**File:** `crates/axiam-api-grpc/tests/grpc_authz_test.rs:481-507`
**Issue:** Odd tasks use action `"write"` expecting deny. The user was granted
`"read"` only, so `"write"` denies — good. But the deny expectation rests on the
grant being action-scoped; if the engine ever defaulted to allow, only the
even/read tasks would catch it via a separate path. The test does correctly
assert per-task `actual == expected`, so this is minor — the mixed allow/deny is
genuinely exercised. No change required; noted for completeness.
**Fix:** None required.

---

_Reviewed: 2026-06-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
