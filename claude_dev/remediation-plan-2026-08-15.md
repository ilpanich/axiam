# AXIAM — Consolidated Remediation Plan (2026-08-15)

> **Purpose.** Full verification of the assumption *"everything in the remediation plans,
> extra activities and the other `claude_dev/` + `benchmarks/` documents is implemented"*,
> and the execution plan for what is **not**. Verified at HEAD `cba87ce` on 2026-08-15 by a
> five-way fan-out (F4 review findings · X1–X6 · run-5 tracks A–F · every older plan ·
> the 11 SDK repos via the GitHub API), each claim backed by file:line or commit evidence.
>
> **Verdict: the assumption holds ~85%.** Every security finding ever raised
> (SEC-002…SEC-092) is fixed or formally dispositioned; X2/X3/X4/X6 are complete server-side;
> the SDK fleet is in sync on CONTRACT 1.17 and `proto/`; all older remediation plans are
> closed except the items below. What remains falls into six clusters:
> 1. **X1 Reactors is half-built** — dispatcher/CRUD/UI exist, but nothing invokes the
>    dispatcher, the normative contract chapter was never written, and the SDK fan-out
>    never happened (confirmed absent in all 11 repos).
> 2. **B4 SCIM 2.0 was never started** (run-5 plan P2; F4 recorded it "not implemented").
> 3. **Measurement debt** — no benchmark cell has been run since run 5; ~10 tasks
>    (A1§5, A2, A3, A4, B1§3, D1, D2, E4 in full, X5 benches) are blocked on one bench pass.
> 4. **X5 certification is built but not exercised** — the conformance suite has never run,
>    so the submission and the fee-waiver letter (operator actions) are gated.
> 5. **A tail of small, precisely-known slivers** — SEC-089's OpenAPI half, frontend
>    residuals (CQ-F30/F09/F11, C3/C4 surfaces), the F3 examples tree, coverage-gate
>    ratchet (T9), SBOM, SDK-Q10, the SAML `Recipient` residual, F-01…F-19 in the SDK repos.
> 6. **No F4 security review exists for anything that landed after 2026-08-10**
>    (X3, X4, X5/X5.1, X6, and eventually X1 + B4).
>
> **Conventions.** Same as the parent plans: one signed commit per task (or tight group),
> per-wave build gate (`cargo build/clippy/test` scoped per crate; frontend `lint + tsc + vitest`),
> disk hygiene per CLAUDE.md, no PR unless asked. Model recommendations follow the
> established policy: **Opus 5** only where failure is a silent security/correctness hole or
> the work is open-ended diagnosis/protocol design; **Sonnet 5** for everything pinned by an
> existing spec, contract, pattern, or fixture. Waves R1→R6 are ordered by risk and
> dependency; R7/R8 are gated on the operator's bench box / docker / hardware.

---

## 0. Verification record (what is DONE — do not redo)

| Document | Status |
|---|---|
| `remediation-plan.md`, `remediation-2026-07-08.md`, `deferred-remediation-plan.md` | Closed (all items code-verified) **except SDK-Q10** → R5.6 |
| `security-analysis-2026-08-02.md` | Closed by its own §24; re-confirmed |
| `security-review-b-track-2026-08-10.md` (F4) | SEC-088 ✅ (`token_exchange.rs:623-641` + regression test), SEC-090 ✅, SEC-092 ✅, deny-override precedence pass ✅ (7 e2e tests, §8 addendum). Residuals → R1 |
| `extra-B-track-features.md` X2/X3/X4/X6 | Complete server-side; named test gaps → R5. X2 SDK fan-out **exceeds** plan (helpers + example pairs in all 11 repos, not just 5 flagships); X4 examples present in exactly ts+go as required |
| `extra-B-track-features.md` X1, X5 | **Open** → R2, R8 |
| `improvement-after-run5-benchmark.md` | A5, A6, C1, C2, D3, D4, D5, E1, E2, E3 done. Rest → R3–R7 |
| `benchmark-improvement-plan.md`, `improvement-after-run4-benchmark.md`, run-4/run-5 runbooks, `UPGRADE-PLAN.md` P0–P2 | Closed/superseded. Surviving: P3.2/P3.3/P3.5 → R7, AMQP harness build-out + server-class re-run → R8 |
| Coverage plans (4 docs) | T1–T8 done; **T9 ratchet never performed** (gate still `--fail-under-lines 80`) → R5.9 |
| `sdk-oidc-sso-plan.md`, `sdk-auth-helpers-plan.md` | Shipped (headers stale — fix in R5.11). **Conformance review F-01…F-19: 18 of 19 open, untracked** → R5.7 |
| `final-code-review.md` / `final-security-review.md` | Backend closed. Frontend CQ-F30/F09/F11 open → R4.7–R4.9. SAML SEC-005 residual open → R1.5 |
| `security-audit.md` | Closed except SBOM → R5.10 |
| `publishing-and-secrets.md` | Closed except §8 downstream-drift gate → R5.8 |
| SDK fleet (11 repos, checked via GitHub API) | CONTRACT 1.17 + `proto/` byte-identical everywhere; DPoP §21.7.2/rule-9 landed fleet-wide 2026-08-15. **Drift: all 11 vendor the 1.15-era `openapi.json`** → R5.8; reactor support absent everywhere (blocked on R2.1) |

`benchmarks/results/` is empty; **no cell has been executed since run 5** — every
"re-measure" clause in every plan is open and consolidated into R7.

---

## Wave R1 — Security & correctness slivers (do first; small, precisely known)

### R1.1 SEC-089 — finish the "document loudly" branch · **Sonnet 5**
F4 offered two options; option 2 (loud docs) was chosen in `866156f` but only half-executed.
- Add a doc comment on `pub audience: Option<String>` in `crates/axiam-oauth2/src/token_exchange.rs:89` stating, in the operator's words, that the audience allow-list **is** the client's `redirect_uris` and that adding a redirect URI also authorises it as a token audience (mirror `docs/api/token-exchange.md:127-139`). Regenerate `sdks/openapi.json` (`axiam-server --dump-openapi --no-default-features`) so the schema description ships.
- The allow-list check now exists at **two** call sites: `token_exchange.rs:582` (same-domain) and `:815` (X4 external, added later with no comment). Add the SEC-089 comment at `:815` and a cross-reference so a future `allowed_token_targets` migration touches both.
- Add one sentence to the `redirect_uris` field docs in `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:27` (the exact place an operator edits the list).
- **Test/acceptance**: `grep "token audience" sdks/openapi.json` non-empty; openapi-drift CI green.

### R1.2 SEC-091 — add the missing back-reference · **Sonnet 5**
The residual write-up landed in `docs/api/token-exchange.md:159-181` instead of
`docs/security-profiles.md` as F4 required. Add 2–3 sentences to
`docs/security-profiles.md` §"Session-revocation posture" (line ~221) stating that token
exchange does not consult revocation, its two bounds (lifetime ≤ subject remaining;
privilege ⊆ subject ∩ client), and linking to `docs/api/token-exchange.md#sec-091`.
Carried rule (record only): if A4-style strict revocation ever extends beyond gRPC, the
exchange path joins the call-site list.

### R1.3 §8.3 hazards — put the warnings where the code is · **Sonnet 5**
Two "open by design" items live only in the review doc; move the invariant into the code:
- `crates/axiam-authz/src/engine.rs:685-688`: comment on `unwrap_or(&empty_ancestors)` —
  widening fallback; unreachable only because the same `has_roles` filter gates both the
  population loop and the consumer; a missed lookup would silently drop an ancestor-scoped deny.
- `crates/axiam-authz/src/engine.rs:732`: either key `grants_by_role` by `(tenant_id, role_id)`
  (preferred — mechanical, the dedup set already uses that key) or state at the declaration
  that cross-tenant batch isolation rests on UUIDv4 uniqueness.
- **Acceptance**: `cargo test -p axiam-authz` green; no behavior change unless the key is widened.

### R1.4 CHANGELOG — record SEC-088…SEC-092 · **Sonnet 5**
`CHANGELOG.md` has no entry for any of the five F4-series findings. Add a security section
under the current unreleased version (fix/decision/doc per finding, one line each).

### R1.5 SEC-005 residual — SAML `SubjectConfirmationData` / `Recipient` validation · **Opus 5**
The last unfixed disclosed security deferral in the whole document set. `crates/axiam-federation/src/saml.rs`
has zero occurrences of `Recipient`/`SubjectConfirmationData`; `NotOnOrAfter` is checked only
via `Conditions` (`saml.rs:497-501`). Without it an assertion minted for a *different* SP at
the same IdP is accepted (Web-Browser-SSO profile §4.1.4.3 violation).
- In the authenticated ACS path, extract `SubjectConfirmation[@Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"]/SubjectConfirmationData`
  and enforce: `@Recipient` equals the SP's ACS URL (same source of truth as the existing
  `Destination` check at `handlers/federation.rs:876-884`), `@NotOnOrAfter` not passed
  (same skew policy as Conditions), and `@InResponseTo` matches when the request was SP-initiated.
  Fail closed; keep the existing binding-signature checks untouched.
- **Tests**: positive vector + three negatives (wrong Recipient, expired SCD, foreign InResponseTo)
  in the existing SAML test suite; the negatives must fail against the current code (write-first).
- **Docs**: flip the deferral rows in `security-audit.md` §7 / `final-security-review.md` SEC-005.
- Opus 5 per the T8 precedent: wrong tests here certify broken signature/confirmation validation.

---

## Wave R2 — X1 Reactors: finish the feature (the largest single gap)

Order matters: R2.1 → R2.2 → R2.3/R2.4 → R2.5/R2.6. Parent-plan constraints apply
(hot-path cells zero-delta; event path within the 262 ms contract).

### R2.1 Normative contract chapter · **Opus 5**
The plan's "§16" was taken by the retry policy (contract 1.8); UMA took §20, FAPI §21.
Write the Reactors chapter as **§22** of `sdks/CONTRACT.md` (contract 1.18), from the
already-implemented `crates/axiam-amqp/src/reactor/protocol.rs` (711 ln, 17 tests) and
`crates/axiam-core/src/models/reactor.rs`:
topology (`axiam.reactor.events` topic exchange, routing key `<tenant_id>.<event>`, queue
`axiam.reactor.q.<tenant>.<reactor>`); §8-v2 HMAC in **both** directions + replay nonce;
reply schema `{decision: allow|deny|mutate, reason?, patch?, require_mfa?}`; per-registration
`timeout_ms` (default 500, max 5000), failure policy, total event budget = min(sum, 5000 ms);
sequential priority ordering, deny short-circuits; the five v1 interceptor events with their
per-event mutable-field allow-lists; hot-path exclusion (authz.check/check_batch/token.introspect)
as a normative MUST-NOT; deferred-runtime carve-out for swift/c/cpp (wire chapter only, per
the lifted §12.6 precedent). Include the §22 conformance checklist and sign/verify round-trip
vectors in `crates/axiam-amqp/tests/fixtures/` next to `v2_reference_vectors.json`.
**Acceptance**: chapter drafted from code, not aspiration — every statement traceable to a
tested line; contract version bumped; breaking-changes log untouched (additive).

### R2.2 Server-side dispatch wiring · **Opus 5**
The central gap: `ReactorDispatcher` (665 ln, 14 tests) and `ReactorGate` exist but **nothing
invokes them** (recorded in `benchmarks/justfile:977-995`). Wire the gate into the five event
sites in `axiam-auth`/`axiam-oauth2` via the `ReactorGate` trait (crates stay broker-agnostic;
`NoopReactorGate` when AMQP is off): `token.pre_issue`, `login.post_auth`, `user.pre_create`,
`user.pre_update`, `grant.pre_assign`. Compose in `axiam-server/src/main.rs`. Requirements
from the plan, all still binding: per-tenant in-flight cap (default 64) with breach ⇒ failure
policy (back-pressure semantics documented); every timeout audited and surfaced as a metric;
`ChainResult.failures` written to the audit trail (currently dropped on the floor — the
frontend health panel depends on it); reactor create/update/delete fires the existing
cache-invalidation hooks so the routing table refreshes within TTL.
**Tests**: per-site gate tests with a mock gate (allow/deny/mutate/timeout paths); the
invalidation test (registry update visible ≤ TTL).
**Acceptance**: a registered interceptor demonstrably vetoes a login in the e2e stack; hot-path
benches show zero delta with reactors registered on other events (measured in R7).

### R2.3 Admin-surface completion · **Sonnet 5**
- gRPC admin service for reactor CRUD (plan requirement; `proto/axiam/v1/` has no reactor
  service). Mirror the REST DTOs; regenerate stubs; buf gates green.
- Per-reactor health: surface recent timeouts/vetoes from the audit trail (now written by R2.2)
  in the existing `GET /api/v1/reactors` response and the frontend `ReactorsPage` (which
  already renders `last_seen_at`).

### R2.4 Integration tests + bench cell · **Sonnet 5**
- Containerized-reactor integration test through real RabbitMQ in `crates/axiam-amqp/tests/`
  (happy path, timeout→failure-policy, forbidden patch field, priority chain, deny short-circuit).
- §22 conformance fixtures (from R2.1) exercised by a test on both sign and verify directions.
- Author the labeled bench cell: `oauth2_client_credentials` with a no-op `token.pre_issue`
  interceptor ("the cost of hooking token issuance", expected +1 AMQP RTT ≈ 1–3 ms p50) —
  runs in R7.

### R2.5 SDK fan-out (8 managed runtimes) · **Sonnet 5** (after R2.1)
Per `extra-B-track-features.md` X1.5, per repo (rust, typescript, python, java, kotlin,
csharp, go, php): `reactor_serve(config, handlers)` helper — connect (TLS per A6/§6),
consume, verify §8 HMAC + replay, decode, dispatch to `fn(event) -> Allow | Deny(reason) | Mutate(patch)`,
sign + publish reply, reconnect/heartbeat (`last_seen_at`), graceful drain; `examples/reactor/`
(HR-lookup claim enrichment + embargoed-region login veto, CI-smoke-run against the compose
stack); a "Writing a Reactor" doc page. Swift/C/C++: no runtime; §22 chapter applies + one
C++ non-normative sample against a common AMQP library. One repo at a time, small PRs,
conformance tests against the §22 vectors.

### R2.6 Reactor product docs · **Sonnet 5**
The plan's "webhook vs listener reactor" comparison table + concept page under `docs/`
(none exists today). Include failure-policy implications and the listener idempotency note.

---

## Wave R3 — B4: SCIM 2.0 provisioning (net-new; last unstarted run-5 task)

### R3.1 `axiam-scim` crate · **Sonnet 5** (large but fully specified)
Per `improvement-after-run5-benchmark.md` B4, verbatim scope: new crate mounted under
`/scim/v2`, tenant-scoped bearer with dedicated `scim:provision` permission; `Users` +
`Groups` CRUD + PATCH per RFC 7644 §3.5.2 (the op subset Okta/Entra actually send:
add/replace/remove on standard attribute paths); filtering subset (`userName eq`,
`externalId eq`, paging); `/Schemas`, `/ServiceProviderConfig`, `/ResourceTypes`; map onto
existing user/group repositories; emit the same webhooks/audit events as native CRUD;
ETag optional-v2; explicitly out: bulk ops, complex filters.
**Tests**: contract tests against recorded Okta and Entra provisioning fixtures; PATCH-op
unit matrix; tenant-isolation tests (SCIM token from tenant A cannot touch tenant B).
**Docs**: provisioning guide with Okta + Entra walkthroughs. **Follow-ons**: SCIM token
management page (C4 surface, → R4.2), rate-limit bucket + flood scenario (A1 family, → R5.2),
F4 tenant-isolation review (→ R6).

---

## Wave R4 — Frontend completion · all **Sonnet 5**

### R4.1 Device verification page (B2 step 3)
`/device` route: enter user code → authenticate → consent → approve/deny, against the
mounted `/api/v1/device/verify` + `/api/v1/device/decide`. The coverage matrix calls this
"the last thing standing between B2 and a working feature". Playwright e2e + vitest.

### R4.2 C4 remaining surfaces (one commit each)
GDPR export/erasure console (`gdpr.rs` — "statutory deadlines make this the highest-value
existing gap"); email config test-send button (`email_config.rs`); scopes CRUD completion;
session/logout settings (per-client `post_logout_redirect_uris` allow-list + back-channel
URI, B5); SCIM token management (after R3.1); **effective-access preview panel** (calls the
check endpoint as a chosen user/resource pair so admins see deny cascades before saving —
required by B1) + red "DENY" badge and inheritance preview on `ResourceTree`.

### R4.3 C3 residual — `FormDialog` error slot
`Input`/`Textarea` already carry `error`/`aria-invalid`/`aria-describedby`; `FormDialog`
(153 ln) exposes no error slot, so the accessible path isn't the default path. Add it and
thread the mutation errors from the pages already using `onError`.

### R4.4 F2 residual — the website still contradicts the shipped engine
`website/src/pages/Benchmarks.tsx:558` ships "our RBAC engine is additive-only in v1.0-beta
(no deny-override)" — false since B1. Fix now; move deny-override/device-flow from "cons"
to "features" (the measured-cost halves of that refresh wait for R7).

### R4.5–R4.9 Final-review frontend residuals
- **CQ-F30 (MED)**: wrap **all** gated route groups in `ProtectedRoute` (currently 4 of ~19;
  unwrapped: tenants, groups, roles, permissions, resources, certificates, webhooks,
  reactors, pgp-keys, oauth2-clients, notification-rules, service-accounts, federation,
  settings — see `frontend/src/router.tsx:98-200`), with a friendly denied state; treat a
  null `/auth/me` after login as hard failure, not `permissions: []`
  (`LoginPage.tsx:246,291`).
- **CQ-F09 (MED)**: `deleteMutation` in `frontend/src/pages/tenants/TenantsPage.tsx:359`
  gets the same `onError` as create/edit.
- **CQ-F11 (LOW)**: drop `noValidate` from the three LoginPage forms (`:370,:427,:557`).
- Fix the stale `frontend-coverage-matrix.md` `permissions` row (deny selector *did* ship).

---

## Wave R5 — Tests, examples, contract & tooling debt

### R5.1 F3 — the examples tree · **Sonnet 5**
No `examples/` directory exists anywhere in the main repo. Create it with the examples every
plan already owes: B1 deny-override walk-through ("grant admin on /fleet, deny on
/fleet/decommissioned") referenced from the five flagship SDK repos; B2 IoT quickstart
(device flow on a headless device, mTLS provisioning as follow-on); B3 mesh-delegation gRPC
end-to-end example (also referenced from `docs/api/token-exchange.md`); B5 RP example app
update. Each example CI-smoke-run against the compose stack so it can't rot.

### R5.2 Missing flood scenarios + limiter test debt · **Sonnet 5**
- k6 flood scenarios + `rl_prod_check.py` rows for: device family (`device_authorization`,
  `device/verify`), `token_exchange`, `/uma2/perm` + uma-ticket grant, and (after R3) SCIM.
- A1's still-owed ≥60 s sustained-flood integration test asserting admitted-rate within the
  bar, and a dedicated limiter CI job running the limiter unit suite.

### R5.3 X2 test gaps · **Sonnet 5**
Keycloak-recorded RPT introspection fixture compat test; property test (an RPT can never
carry a (resource, scope) pair the live engine would deny at mint time — proptest in
`axiam-oauth2`, seeded engine).

### R5.4 X4 cross-vendor proof · **Sonnet 5**
Add a Keycloak service to `docker/docker-compose.e2e.yml`; e2e test exchanging a token
minted by real Keycloak (the test file itself says this belongs to the compose suite,
`external_token_exchange_test.rs:19-27`). Reuse `benchmarks/targets/keycloak` config.

### R5.5 X5.1 remaining gap row — profile-driven lifetime bundle · **Sonnet 5**
`fapi.rs`'s nine-row profile table has no lifetime row: make `profile: fapi2` also bundle
refresh-token/code lifetimes and `exp` bounds (config plumbing over the existing pattern;
escalate to Opus 5 only if semantics questions surface).

### R5.6 SDK-Q10 — the last deferred contract item, now a breaking decision · **Opus 5 decision, Sonnet 5 execution**
`proto/axiam/v1/authorization.proto:43` still has `deny_reason`; B1 added `reason_code = 3`
beside it, and `sdk-buf-gates.yml` now runs `buf breaking`. Decide: rename + major bump vs
deprecate-and-add vs formally accept divergence in CONTRACT §2 (recommended default:
**deprecate-and-add** — add `reason`, mark `deny_reason` deprecated, contract erratum, remove
at 2.0). Then the mechanical halves: TS `resourceType` removal, `AccessDecision` shape
reconciliation, gRPC `subject_id` optionality — per `deferred-remediation-plan.md` §C2.

### R5.7 SDK conformance follow-ups F-01…F-19 · **Opus 5 for F-01/F-06, Sonnet 5 for the rest**
18 of 19 items from `sdk-oidc-sso-conformance-review.md` §4 are open and tracked nowhere
newer. Blocking first: **F-01** rust `oidc_refresh` single-flight (broadcast-channel
leader/waiter, `Sensitive<T>` manual Clone, ≥5-caller burst test asserting one wire call) and
**F-06** PHP double-refresh after guard re-acquire — both concurrency defects in a security
control. Then the highs (F-02/F-03 java+kotlin `Sensitive.expose()` visibility, F-04 rust
`+` vs `%20`, F-05 rust `sso_complete` cookie absorb, F-07 `#[non_exhaustive]`), then
mediums/lows per the review's file:line list. One PR per repo.

### R5.8 SDK artifact sync + the missing downstream gate · **Sonnet 5**
- Re-vendor `sdks/openapi.json` into all 11 SDK repos (all vendor the 1.15-era blob
  `ff6a0a02`; main is `0d64dace` — missing `jwks`, `jwks_uri`, `dpop_bound_access_tokens`,
  `dpop_require_nonce`, `private_key_jwt` variant, `cnf.jkt`). Spot-check repos with
  checked-in gRPC stubs regenerated against the 1.17 protos (only go's commit claims it).
- Close `publishing-and-secrets.md` §8: a scheduled CI job in the main repo comparing the
  four vendored artifacts' blob hashes across the 11 repos via the GitHub API (precedent:
  `scripts/check-remediation-evidence.py`), failing with a per-repo staleness report. This
  exact class of drift is what it would have caught this week.

### R5.9 T9 — coverage re-measure + ratchet · **Sonnet 5**
`coverage.yml:130` still `--fail-under-lines 80`. Run full-workspace `cargo llvm-cov`
exactly as CI does, confirm TOTAL (target ≥88.5%), ratchet to (achieved − 2), add
`coverage.thresholds.lines` to `frontend/vitest.config.ts` (still absent).

### R5.10 SBOM (CRA/ISO A.5) · **Sonnet 5**
Zero SBOM tooling in the repo. Emit CycloneDX (or SPDX) for the Rust workspace
(`cargo cyclonedx` or syft) + the frontend npm tree; attach to `release.yml` artifacts;
flip `docs/compliance/FINDINGS.md` SBOM-01 and the ASVS checklist row.

### R5.11 Documentation truthing sweep · **Sonnet 5**
One commit fixing every stale status line found during verification:
`new-feature-bench-cells.md` status table (device-flow REST **is** mounted since `ffaaed1`;
token exchange **is** implemented since `4dbd832` — both cells are unblocked-but-unwritten);
`improvement-after-run5-benchmark.md` §B6 "X1–X5" → X1–X6; stale "PLAN — not yet
implemented" headers on `sdk-oidc-sso-plan.md` and `sdk-auth-helpers-plan.md`;
`claude_dev/performance-report.md` A2 post-mortem section (fix landed in `98a8b79`,
five→three round trips; measurement pending R7).

---

## Wave R6 — F4-bis: security review of everything post-2026-08-10 · **Opus 5**

Mandatory per `extra-B-track-features.md` ("F4 review mandatory" on X1, X4, X6; X3's
BLOB-chain verification and X5.1's protocol work "included in the F4 Opus 5 security
review") — and none of it has happened. One consolidated review in the established
`security-review-*.md` format, findings continuing the SEC- sequence, covering:
- **X4** external-IdP token exchange (`crates/axiam-federation/src/token_exchange.rs`, 833 ln)
  — read in full; the invariants (no transitive exchange, never-widen, lifetime min) are the
  attack surface.
- **X5/X5.1** — `dpop.rs` (932 ln), `private_key_jwt.rs` (1040 ln), `mtls.rs`, binding
  enforcement order in the token path.
- **X3** — MDS3 BLOB chain verification (`crates/axiam-pki/src/mds/blob.rs`) and the
  enforcement diff in `axiam-auth`.
- **X6** — the layered single-use mechanism across the four repositories + engine attestation.
- **X1** — after R2.2 lands (the dispatcher becomes reachable code; review the gate wiring,
  patch allow-list enforcement, and the HMAC/replay path under mutation).
- **B4 SCIM** tenant isolation — after R3.1 (F4's brief named it; it didn't exist).
- Promote the three **sampled-only** B-track surfaces to read-in-full: `par.rs`, AMQP TLS
  config/connection, gRPC strict-revocation interceptor.

---

## Wave R7 — The measurement pass (one bench session; **operator's G-box** + Sonnet 5)

Everything below is the same blocked resource: one full benchmark session. Prep (scenario
authoring, runbook) is Sonnet 5; execution needs the operator's hardware/docker. Publish
every cell honestly per project culture; then flip the docs.

| Cell / measurement | Source obligation |
|---|---|
| `rl-prod` full pass — §7 table must flip to PASS on every row (or documented burst label) | A1 §5 |
| `token_refresh` re-measure (fix `98a8b79` landed; target back toward run-4 numbers, else document the trade honestly) | A2 §5 |
| CP-3 SurrealDB tuning sweep (knob→throughput table into `surrealdb-tuning-report.md` §9 — currently an explicitly empty skeleton) | A3 §1 |
| `grpc-strict-revocation` labeled cell (scripted, never run) | A4 §2 |
| `authz-deny-present` two arms — B1's ±2% no-deny gate + honest with-deny cost | B1 §3 |
| `seed-scale` 1×/10×/100× | E3/E4 |
| `device-flow-poll` + `token-exchange` cells — **author the two missing k6 scenarios first** (features shipped; scenarios were never written) | E4 |
| `amqp-tls` vs plaintext sanity cell (optional) | A6 §6 |
| Reactor hook-cost cell (from R2.4) + hot-path zero-delta proof | X1.6 |
| `cargo bench -p axiam-auth` — certificate + DPoP binding numbers | X5 |
| Python SDK median-of-3 re-run (uvloop fix landed; target p50 ≤ 20 ms, p95 ≤ +15 ms vs wire) | D1 |
| C++ reconnect-tail: packet capture diagnosis (handshakes/1k requests vs go), keep-alive audit, re-bench to p95 ≤ 3× p50; also verify the **C** SDK honors `SDK_BENCH_CONCURRENCY` on refresh | D2 — diagnosis is **Opus 5** |
| `oidc_discovery` scenario (DiscoveryCache landed without before/after) | UPGRADE-PLAN P3.2 |
| MFA verify scenario (TOTP seeding; canonical op, unmeasured) | UPGRADE-PLAN P3.3 |
| SDK gRPC-path ops (`check_access_grpc`) + aggregator unknown-op tolerance | UPGRADE-PLAN P3.5 |

**After the pass** (Sonnet 5): regenerate the §7 limiter table and rate-limit sizing tables;
PUBLIC/PRIVATE analysis updates; `performance-report.md`; the website comparison-page
"measured cost" halves (R4.4 shipped the correctness half); A2 CI guard (throughput or
budget-test wired as a named job).

---

## Wave R8 — Certification & operator-gated backlog

| # | Item | Owner / model | Detail |
|---|---|---|---|
| R8.1 | **Run the FAPI conformance suite to green** | Sonnet 5 (needs docker) | Harness is complete (`just conformance-*`, 3 plan templates, CI workflow, runbook). `docs/conformance/` is empty — "the only [entry] blocking submission" per the runbook. Iterate on findings; mechanical fixes Sonnet 5, protocol-semantics findings escalate to Opus 5. Keep final HTML reports in `docs/conformance/`. |
| R8.2 | Fee-waiver letter to the OpenID Foundation | **Operator** | Letter is final in `extra-B-track-features.md` §X5.4 and cleared for sending as written (`fapi-certification-submission.md:56-70`). Fill the two placeholders, attach the green report from R8.1, send. Wait for the answer before paying anything. |
| R8.3 | Certification submission | **Operator** | Follow `fapi-certification-submission.md` steps 1–5 (digest-pin release image → CI against digest → publish receipts → submit → post-mark duties). Gated on R8.1 + a signed release tag. |
| R8.4 | X3 recorded-attestation fixtures | **Operator** (hardware) | The accept-half of X3's acceptance needs a real YubiKey direct-attestation capture (the webauthn-rs corpus was checked and documented unusable — `webauthn_attested_tests.rs:7-33`). Capture from a device, then Sonnet 5 wires the fixture tests. |
| R8.5 | AMQP async-authz load harness build-out | **Opus 5** (deferred backlog) | Design doc landed; the publisher/consumer measurement tool was deferred twice, deliberately. Now the only unmeasured transport — and it carries the v2 replay protocol. Build when bench time exists. |
| R8.6 | Server-class hardware re-run | **Operator** (blocked on budget) | Unchanged from `benchmark-improvement-plan.md` E3. Listed so it isn't silently dropped. |

---

## Execution order & gates

```
R1 (security slivers)          — no dependencies; do first
R2.1 → R2.2 → {R2.3, R2.4} → {R2.5, R2.6}      [gate: reactor veto works e2e]
R3 (SCIM)                       — parallel with R2
R4 (frontend)                   — parallel; R4.2's SCIM page waits on R3
R5 (tests/contract/tooling)     — parallel; R5.8's re-vendor bundles R2.1's contract 1.18
R6 (F4-bis)                     — after R2.2 + R3.1 land [gate: no new HIGH open]
R7 (bench pass)                 — after R2.4 + R5.2 scenarios exist; operator schedules
R8 (certification/operator)     — R8.1 whenever docker is available; R8.2/R8.3 after R8.1
```

Cheapest-adequate model totals: **Opus 5** only for R1.5, R2.1, R2.2, R5.6 (decision),
R5.7 (F-01/F-06), R6, R7 (D2 diagnosis), R8.5 — everything else Sonnet 5 or operator.
