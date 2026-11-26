# Fix plan — open issues in all twelve repositories (2026-11-26)

> **Status: PLANNED.** Nothing in this document has been executed. As each task
> lands, add an `EXECUTED` block at the head of its section (what shipped, which
> tests went in, what the plan did not anticipate), in the form
> [`security-audit-2026-11-14-fix-plan.md`](security-audit-2026-11-14-fix-plan.md)
> uses.

This plan covers every issue that was open on 2026-11-26 in `ilpanich/axiam` and
in the eleven `ilpanich/axiam-<lang>-sdk` repositories: **26 issues**, 15 on the
server and one per SDK. Twenty-four of them are the low and nit follow-ups of the
2026-11-14 security-audit remediation (filed under the owner's rule that low and
nit findings after a medium-clean review round become issues). The other two are
Phase 23 leftovers that depend on the maintainer.

The executing session uses **Opus 5.5 as orchestrator**. The orchestrator
delegates each task to a sub-agent on the model named in §3, runs the review gate
of §1.6, and writes the `EXECUTED` blocks. It does not implement tasks itself.

---

## 0. Inventory

### Server (`ilpanich/axiam`)

| Issue | Severity | Subject | Task |
|---|---|---|---|
| #872 | low | No test for same-second acceptance of unversioned tokens (QR22-1) | OI-04 |
| #873 | low | OPAQUE `login/finish` duplicates the credential-superseded rule (QR22-2) | OI-04 |
| #874 | nit | Deployment guide, SA-06 paragraph (QR22-3) | OI-06 |
| #877 | low | Suspended tenant: federated sign-in provisions users before the refusal (SR5-1) | OI-02 |
| #878 | low | Suspended tenant: lockout race confirms a correct password (QR5-1/SR5-2) | OI-01 |
| #879 | nit | Stale wording, deployment README and auth handler comments | OI-06 |
| #880 | cross-SDK | SDKs refuse every genuine back-channel logout token (`kid`) | OI-05, then every SDK task |
| #881 | cross-SDK, docs | `AuthzRequester` unsigned-response opt-out is documented wrongly | OI-05, then the seven AMQP SDK tasks |
| #882 | cross-SDK | AMQP event consumers verify the HMAC over a re-serialization | OI-11, OI-12, OI-13, OI-16 (pins in OI-10, OI-14, OI-17) |
| #883 | cross-SDK, low | `AuthzRequester` security events omit routing key and tenant | OI-05, then the seven AMQP SDK tasks |
| #889 | low | Audit redaction misses `export//<token>` (SR2-1, QR2-4) | OI-03 |
| #890 | nit | Stale comments (`reset_mfa`, gRPC cap test, CSRF/session wording) | OI-06 |
| #891 | low/nit | Upgrade-note and admin-doc corrections (nine items) | OI-06 |
| #561 | Phase 23 G-10 | Benchmark currency: runs 6, 6b and 6c in the three comparison documents (draft and website already done) | OI-07 |
| #513 | Phase 23 G-1 | OpenID Basic OP and FAPI 2.0 certification submissions | **no task** (§7) |

### SDKs (one issue per repository, each a verbatim reviewer report)

| Repository | Issue | Findings in the issue | Task |
|---|---|---|---|
| `axiam-typescript-sdk` | #167 | TYP-R3-1, TYP-R3-2, the "Nits" section | OI-10 |
| `axiam-python-sdk` | #110 | PYT-R1-1 … PYT-R1-6, GLUE-R1-4, GLUE-R1-5 | OI-11 |
| `axiam-php-sdk` | #92 | PHP-R1-1 … PHP-R1-7, the GLUE section | OI-12 |
| `axiam-csharp-sdk` | #125 | CSH-R5-1, CSH-R5-2 | OI-13 |
| `axiam-java-sdk` | #133 | JAV-R1-1 … JAV-R1-8, the GLUE section | OI-14 |
| `axiam-kotlin-sdk` | #99 | KOT-R1-1 … KOT-R1-7, the GLUE section | OI-15 |
| `axiam-go-sdk` | #111 | GO-R1-1 … GO-R1-9 | OI-16 |
| `axiam-rust-sdk` | #152 | RUS-R1-1 … RUS-R1-9 | OI-17 |
| `axiam-cplusplus-sdk` | #89 | CPL-R1-6 (§11.2 rule 11), CPL-R5-1 | OI-18 |
| `axiam-c-sdk` | #87 | C-R3-1, C-R3-2, C-R3-3 | OI-19 |
| `axiam-swift-sdk` | #91 | SWI-R1-1 … SWI-R1-5, observations O-1, O-2, O-3 | OI-20 |

State of the trees on 2026-11-26: the server is at **1.3.1** with an empty
`[Unreleased]` changelog section and **CONTRACT 1.68**; every SDK's last tag is
`v1.3.1` and its **1.4.0 is unreleased** (`[Unreleased]` in each `CHANGELOG.md`).
Public API corrections in the SDKs are therefore still free: they amend an
unreleased version. One server pull request is open and is **not** part of
this plan: #893 (`claude/db-query-optimization`). Do not touch its branch. If it
merges during execution, merge `origin/main` into the working branch (no rebase).

---

## 1. Ground rules for every task

### 1.1 The issue is the specification

Each sub-agent starts by reading its issue in full with
`gh api repos/ilpanich/<repo>/issues/<n> --jq .body` (only `gh api` works in the
cloud sandbox; `gh issue` is refused). The SDK issues carry the reviewer's
verbatim report, with file, line, failure scenario and suggested fix for every
finding. This plan adds the decisions, the scope and the cross-repository
ordering; where it is silent, the issue's suggested fix is the instruction.

Line numbers in the issues were taken on the review branch. Locate each site by
the quoted symbol, not by the number.

### 1.2 Test first

For every finding that changes behaviour: write the regression test, run it
against the unfixed code, **watch it fail**, then fix and watch it pass. Record
the observed failure in the `EXECUTED` block. If the test passes on unfixed
code, the finding did not reproduce: change no production behaviour, keep the
test as a pin, and report it. Never delete, skip or `#[ignore]` a test to get
green; a test that pinned the old behaviour is rewritten to the secure
expectation.

Documentation-only findings need no test, but each corrected statement must be
checked against the code it describes, and the `EXECUTED` block names the file
and symbol it was checked against.

### 1.3 Repositories, branches, commits

- Work on the branch the executing session designates, in each repository.
  Never commit to `main`.
- One **signed** commit per task. Message:
  `fix(<scope>): <summary> (OI-NN, #<issue>[, #<issue>…])` for code,
  `docs(<scope>): …` for documentation-only tasks. No model identifier in any
  commit, PR or code comment.
- One pull request per repository, opened by the close-out task (OI-30) after
  the gates are green. The body lists `Closes #<n>` for that repository's issues
  and follows the repository's PR template if one exists.
- **Merge order matters for the cross-SDK issues.** #880–#883 live in
  `ilpanich/axiam` but are finished only when the SDK work is merged. The
  server PR therefore says `Closes #880, #881, #882, #883` and its body states
  that it merges **after** the eleven SDK PRs. Issues close on merge, never
  before (project rule).

### 1.4 Build hygiene (server)

Follow *Build & Disk Hygiene* in `CLAUDE.md` exactly: `cargo clean` between
tasks (never during one), narrowly scoped `cargo test -p <crate> --test <name>`,
the swagger-ui placeholder after every `target/` wipe,
`apt-get install -y protobuf-compiler` before anything that builds
`axiam-server`, `--no-default-features` where libxml2 is absent, and cargo's exit
code captured from a log, not from a pipeline. Server tasks run **sequentially**:
they share one `target/`.

No task in this plan is expected to change a REST request or response type. If
one does, regenerate `sdks/openapi.json` and `sdks/management-registry.json`
with the procedure in `CLAUDE.md`, in the same commit.

### 1.5 Definition of done (every task)

- Every finding of the task is either fixed or rejected with a written
  justification in the `EXECUTED` block. Nothing is dropped silently.
- Regression tests per §1.2.
- Server: `cargo fmt -p <crate> -- --check` and
  `cargo clippy -p <crate> -- -D warnings` clean for each touched crate, and
  `python3 scripts/check-crate-layering.py` clean if a `Cargo.toml` changed.
  SDK: the lint, format and test commands that repository's CI workflow runs.
- SDK: the entry goes into the existing `[Unreleased]` / 1.4.0 section of
  `CHANGELOG.md`. No version bump, no tag.
- No unrelated refactoring.

### 1.6 Review gate (bounded)

These tasks *are* the low and nit tail of a review gate that ran for up to 41
rounds. The gate here is therefore bounded, so that it converges (decision D-6):

1. After Wave A, and after each SDK task of Wave B, one **Opus 5.5** reviewer
   that wrote none of the code reviews the complete diff for code quality and
   security together. It receives the diff, the task section of this plan and
   the issue bodies, not the implementer's summary. It checks in particular
   that each regression test really fails without its fix, and that no secret,
   token or personal datum reaches a log or an error.
2. **Medium or higher:** must be fixed; the review re-runs on the fix. No limit
   on rounds.
3. **Low and nit:** fixed in the same round when the fix is local (a few
   lines, no new design). Otherwise rejected with a written justification.
   **At most two review rounds** are spent on low and nit findings. Whatever is
   still open after round two is listed in the `EXECUTED` block and, only if it
   is security-relevant, filed as **one** follow-up issue per repository.
4. Fixes go to an agent on the model the task used, one signed commit per
   round: `fix(review): <summary> (OI wave X, round M)`.
5. The gate result (findings, resolution, rounds) is recorded under the wave's
   heading in this document.

---

## 2. Decisions

These points have more than one defensible answer. Each carries the
recommendation this plan is written against. **The orchestrator confirms D-1
with the owner before starting OI-05**; the others are applied as written unless
the owner says otherwise.

| # | Issue | Decision (recommended) | Alternative rejected |
|---|---|---|---|
| D-1 | #880 | **The server adds `kid` to back-channel logout tokens** (contract 1.69). A logout token is the one "no `kid`" token that a relying party, not AXIAM, verifies through the JWKS; standard OIDC libraries select the key by `kid`, and a kid-less token is ambiguous whenever the JWKS holds two keys (rotation). The SDKs keep requiring a `kid` on this path, so a logout token from a pre-1.69 server is refused, which is already today's behaviour. | The contract tells SDKs to try every EdDSA key for a kid-less logout token: eleven implementations of a fallback that rule 12 has just removed elsewhere, and no help for third-party RP libraries. |
| D-2 | #881 | **Keep the unsigned-response opt-out; correct its documentation.** State that the requester needs a server of 1.68 or later, and describe the opt-out by what the server really does (OI-05 establishes this from the SA-15 code). If OI-05 finds that no supported server configuration can send an unsigned response to a `reply_to` queue, the opt-out is **removed** from all seven SDKs instead (1.4.0 is unreleased). | Leaving a rolling-upgrade claim that cannot be true. |
| D-3 | #89, #91 (O-3) | **C++ and Swift implement CONTRACT §11.2 rule 11 in full**: 11(b) (a MUST), `require_scope` (11(d), a SHOULD where `require_role` ships) and the documentation points. Their READMEs then state §11.2 conformance without a carve-out. This reverses the C++ README's "11(d) declined". | Shipping two SDKs with a documented exception to a rule the other nine follow. |
| D-4 | #111 (GO-R1-2), #91 (O-1), #133 (JAV-R1-3), #99 (KOT-R1-5) | **The unknown-`kid` cooldown of §12.4 rule 2 is in scope** in Go, Swift, Java and Kotlin, with the contract's own conformance test (fifty unknown `kid`s in one window cause at most one fetch; a rotated key is accepted after one fetch). | Treating it as pre-existing and out of scope: §10.1 rule 12 cites the cooldown directly. |
| D-5 | #882 | **Verify over the received bytes and dispatch those same bytes** in the Go, Python, C# and PHP event consumers, as the Java consumer and the Go requester already do. Rust, TypeScript and Java get a pin test only. | Fixing the encoder differences one by one (`ensure_ascii`, HTML escaping): the class stays open. |
| D-6 | all | The bounded review gate of §1.6. | The unbounded gate of the audit plan, which would regenerate this backlog. |
| D-7 | #513 | **No development task.** Every code task of G-1 is done; what remains is the signed Certification of Conformance, which needs the maintainer's identity. The issue stays open (§7). | Closing it without a submission. |

---

## 3. Task overview

Model column: **Opus 5.5** where the task crosses several crates, defines a rule
that other tasks port, or where a wrong fix opens a new hole; **Sonnet 5.5**
where the change is local and the issue or this plan specifies it completely.

### Wave A — server (`ilpanich/axiam`, sequential, in this order)

| Task | Issues | Summary | Model |
|---|---|---|---|
| OI-01 | #878 | Read-only lock check before the suspended-tenant admission | Sonnet 5.5 |
| OI-02 | #877 | Suspended-tenant admission before federated provisioning | Opus 5.5 |
| OI-03 | #889 | Unmatched-path redaction over non-empty segments; one pattern list | Sonnet 5.5 |
| OI-04 | #872, #873 | One credential-superseded rule; the missing tests | Sonnet 5.5 |
| OI-05 | #880, #881, #883 | Logout-token `kid`, CONTRACT 1.69, cross-SDK rules (Appendix A) | Opus 5.5 |
| OI-06 | #874, #879, #890, #891 | Documentation and comment corrections | Sonnet 5.5 |
| OI-07 | #561 | Runs 6, 6b and 6c in the comparison documents; website spot-check | Sonnet 5.5 |

### Wave B — SDKs (one task per repository, parallel)

| Task | Repository | Issues | Model |
|---|---|---|---|
| OI-10 | `axiam-typescript-sdk` | #167, #880, #881, #882 (pin), #883 (verify) | Sonnet 5.5 |
| OI-11 | `axiam-python-sdk` | #110, #880, #881, #882, #883 | Sonnet 5.5 |
| OI-12 | `axiam-php-sdk` | #92, #880, #881, #882, #883 | Sonnet 5.5 |
| OI-13 | `axiam-csharp-sdk` | #125, #880, #881, #882, #883 | Sonnet 5.5 |
| OI-14 | `axiam-java-sdk` | #133, #880, #881, #882 (pin), #883 | Sonnet 5.5 |
| OI-15 | `axiam-kotlin-sdk` | #99, #880 | Sonnet 5.5 |
| OI-16 | `axiam-go-sdk` | #111, #880, #881, #882, #883 | Opus 5.5 |
| OI-17 | `axiam-rust-sdk` | #152, #880, #881, #882 (pin), #883 | Sonnet 5.5 |
| OI-18 | `axiam-cplusplus-sdk` | #89, #880 | Sonnet 5.5 |
| OI-19 | `axiam-c-sdk` | #87, #880 | Sonnet 5.5 |
| OI-20 | `axiam-swift-sdk` | #91, #880 | Sonnet 5.5 |

Wave B starts when OI-05 is committed **and** the re-vendoring step of §5.0 is
done. OI-10 runs first for one reason only: it records the redirect-encoding
rule (TYP-R3-1) in `docs/login-glue-binding.md`, which OI-11 to OI-15 then check
their ports against. OI-16 to OI-20 may start together with OI-10.

OI-16 is the only SDK task on Opus 5.5: Go is the reference implementation of
the AMQP requester, and its findings include a Unicode key-folding mismatch with
`encoding/json`, a goroutine and consumer leak, and the JWKS cooldown, each of
which is easy to fix in a way that looks right and is not.

### Wave C — close-out

| Task | Summary | Model |
|---|---|---|
| OI-30 | Cross-repository consistency check, final regression, pull requests | Sonnet 5.5 |

**Totals:** 19 tasks — 3 on Opus 5.5, 16 on Sonnet 5.5 — plus one Opus 5.5
review per gate (one for Wave A, eleven for Wave B).

---

## 4. Wave A — server

### OI-01 — #878: lockout race on a suspended tenant · Sonnet 5.5

> **EXECUTED (2026-11-26, Sonnet 5.5), commit `95e3610`.** New private helper
> `refuse_if_locked_now` in `crates/axiam-auth/src/service.rs` runs the
> read-only `admit_unless_locked(tenant, user, false)` and answers
> `InvalidCredentials` on a lock in force; it runs before `admit_tenant` in step
> 3b of `complete_authenticated_login` and in the directory arm of
> `login_directory_account`. The writing step 4 stays after `admit_tenant`.
>
> - **Regression tests** (`crates/axiam-auth/tests/directory_provisioning_test.rs`,
>   beside the QR3-1 suspended-tenant tests, not `auth_service_test.rs` as the
>   plan guessed): `qr5_1_a_locked_account_on_a_suspended_tenant_answers_a_correct_password_uniformly`
>   (password path, `LockAfterRead` repository wrapper) and
>   `qr5_1_a_locked_directory_account_on_a_suspended_tenant_answers_uniformly`
>   (directory arm, `LockingDirectory` stub that commits the lock during the
>   bind). Unfixed code: both panic with `a lock in force on a suspended tenant
>   must not be answered tenant_suspended`. Fixed: both pass.
> - **Neighbours** already pinned, unchanged and passing: `qr3_1_a_local_login_on_a_suspended_tenant_runs_no_post_credential_bookkeeping`,
>   `qr3_1_a_directory_login_on_a_suspended_tenant_maps_no_groups` (unlocked +
>   correct password → `tenant_suspended`), `qr3_1_a_first_directory_login_on_a_suspended_tenant_creates_no_account`
>   (wrong password → uniform 401, failure counted).
> - **Verification:** `directory_provisioning_test` 27 passed;
>   `auth_service_test` 94; `lockout_race_test` 3; `directory_account_test` 12;
>   fmt and `clippy --all-targets -D warnings` clean for `axiam-auth`.
> - **Not anticipated:** (1) the directory arm already checked the lock before
>   contacting the directory, so the race reproduces only with a lock committed
>   mid-bind; (2) `complete_authenticated_login` is shared with OPAQUE,
>   directory JIT and federation, which therefore get the same ordering.

**Why Sonnet.** One function, and the issue gives the exact reordering.

**Where.** `crates/axiam-auth/src/service.rs`: the password path (step 3b
`admit_tenant`, before step 4 `admit_unless_locked`) and the directory arm.

**Do.**
1. Test first, in `crates/axiam-auth/tests/auth_service_test.rs` (or the file
   that holds the suspended-tenant sign-in tests): a **suspended** tenant, a
   user that is **already locked**, the **correct** password. Assert the uniform
   `InvalidCredentials` result (HTTP 401 shape), not `tenant_suspended`. Add the
   same case for the directory arm. Both must fail on the unfixed code.
2. Insert the read-only check `admit_unless_locked(tenant, user, false)` before
   `admit_tenant`; on failure answer `InvalidCredentials`. Keep the writing
   step 4 where it is, after `admit_tenant`.
3. Check the two neighbours: a suspended tenant with an unlocked user and the
   correct password still answers `tenant_suspended`; a wrong password still
   answers the uniform 401 and still counts toward the lockout.

**Verify.** `cargo test -p axiam-auth --test auth_service_test`, fmt and clippy
for `axiam-auth`.

### OI-02 — #877: federated sign-in provisions before the refusal · Opus 5.5

**Why Opus.** It crosses `axiam-api-rest` and `axiam-federation`, touches three
callbacks (OIDC, OAuth2 social, SAML), and has a constraint that a local fix
violates easily: the check must not move to `consume_login_state`, which would
reopen the anonymous suspension oracle closed by SR1-8.

> **EXECUTED (2026-11-26, Opus 5.5), commit `c6ede3d`.** `OidcFederationService`
> and `SamlFederationService` take an optional `SharedTenantAdmission`
> (`with_tenant_admission`, the `AuthService` pattern; `axiam-federation` uses
> only the `axiam-core` port, no `Cargo.toml` changed, layering script OK). The
> shared helper `oidc::admit_tenant` runs after the upstream answer verified and
> before provisioning: in `handle_callback_for` (after signature, nonce, claim
> mapping), `handle_oauth2_callback` (after userinfo and the verified-email
> rule) and `handle_saml_response_for` (after signature, profile and replay
> checks). New `FederationError::TenantSuspended` → `AxiamError::TenantSuspended`
> (403 `tenant_suspended`). The `create_session_and_tokens` check stays as a
> backstop; nothing moved into `consume_login_state`. Wired in
> `axiam-server/src/boot.rs` for both services.
>
> - **Regression tests** (each also asserts 403, no session cookie, no
>   federation link, zero `login.post_auth` reactor calls). Unfixed code, each:
>   `no user may be provisioned in a suspended tenant  left: 1 right: 0`.
>   `federation_first_time_sso_test::an_oidc_sign_in_to_a_suspended_tenant_is_refused`
>   (extended), `…::a_social_sign_in_to_a_suspended_tenant_provisions_nothing`,
>   `sec095_federated_login_gate_test::saml::a_saml_acs_sign_in_to_a_suspended_tenant_provisions_nothing`
>   (the SAML harness lives there, not in the first-time-SSO file).
> - **Oracle pins (step 4)**, pass before and after: unverified OIDC callback,
>   social callback and SAML assertion answer identically for a suspended and an
>   active tenant. Positive controls prove the count queries see real rows.
> - **Step 5, other paths:** native provider-ID-token grant — not vulnerable
>   (`live_tenant` refuses before the token is verified), pinned by
>   `provider_id_token_test::a_native_sign_in_to_a_suspended_tenant_provisions_nothing`;
>   X4 token exchange JIT — not vulnerable (`authenticate_client` first, covered
>   by `tenant_suspension_test`); directory JIT — not vulnerable (QR3-1);
>   Apple form callback, SAML form ACS, admin `oidc/callback` and `saml/acs` —
>   fixed by the same service change; every other `CreateUser` in production
>   source is `#[cfg(test)]`; WebAuthn, OPAQUE, password, mTLS do not provision.
> - **Verification:** libxml2/xmlsec1/protoc installed with apt, so SAML ran
>   with default features. `federation_first_time_sso_test` 11,
>   `sec095_federated_login_gate_test` 58, `provider_id_token_test` 25,
>   `federation_login_providers_test` 9 passed; `--no-default-features`: 11 and
>   4 passed; `axiam-federation --lib` 418 passed; fmt and clippy
>   (`--all-targets -D warnings`, both feature sets) clean for
>   `axiam-federation`, `axiam-api-rest`, `axiam-server`. **Not run:** the
>   `axiam-server` integration tests; `boot.rs` was compiled and linted only.
> - **Not anticipated:** (1) the admission is optional, like `AuthService`'s:
>   a service built without it admits (test harnesses), and no test exercises
>   the `boot.rs` wiring itself; (2) the SAML refusal spends the assertion (the
>   replay row is written first), so it cannot be replayed after the suspension
>   lifts; (3) the T-510 residual line is left for OI-06, as this plan says.

**Where.** `crates/axiam-api-rest/src/handlers/federation_login.rs` and its
sibling callbacks; `crates/axiam-federation/src/oidc.rs`, `saml.rs`; the
`provision_or_link_identity` and `sso_login_post_auth` call sites.

**Do.**
1. Test first: extend `federation_first_time_sso_test.rs` (the suspended-tenant
   case) to assert that after the callback **no user row and no federation link**
   exist and that the post-auth reactor did not run, in addition to the 403.
   Cover the OIDC callback, the OAuth2 social callback and the SAML ACS. Each
   must fail on unfixed code (the user is created today).
2. Pass the existing `SharedTenantAdmission` to the point where the upstream
   token or assertion **has validated** and before `provision_or_link_identity`.
   Refuse there with the same `tenant_suspended` error the session step uses.
   Keep the later check in `create_session_and_tokens` as a backstop.
3. Respect the crate layering: `axiam-federation` may take the admission as a
   trait object or a closure defined in a lower layer; it must not depend on
   `axiam-api-rest`. Run `python3 scripts/check-crate-layering.py`.
4. Confirm the oracle stays closed: an unauthenticated request (no valid
   upstream assertion) to a suspended tenant's callback must answer exactly as
   it does for an active tenant. Add or extend the test that pins this.
5. Look for further sign-in paths that provision before admitting (native
   provider-ID-token grant, directory just-in-time provisioning, SCIM is not a
   sign-in). Fix any with the same pattern and its own test; report the list.

**Verify.** `cargo test -p axiam-api-rest --test federation_first_time_sso_test`
(with `--no-default-features` too, for the SAML-off build), the SAML test file
that covers the ACS, fmt, clippy, layering script.

### OI-03 — #889: unmatched-path redaction · Sonnet 5.5

**Where.** `crates/axiam-audit/src/middleware.rs`: `redacted_unmatched_path`,
`BEARER_PATH_PREFIXES`, `REDACTED_PATH_PARAMETERS`; the caller in
`request_span.rs`.

**Do.**
1. Add `/api/v1/account/export//super-secret-handle` to the URI list of
   `a_token_path_segment_is_redacted_even_when_no_route_matches`, plus a
   triple-slash and a trailing-slash spelling. Watch it fail.
2. Compare against the previous two **non-empty** segments.
3. QR2-4: derive `BEARER_PATH_PREFIXES` and `REDACTED_PATH_PARAMETERS` from one
   list of patterns if that is a small change; otherwise add a test that fails
   when a `{token}` path parameter has no matching prefix entry. Qualify the
   "Fails **closed**" doc comment to say what it covers.
4. Confirm the tracing span uses the same function, so the fix reaches both.

**Verify.** `cargo test -p axiam-audit --lib`, fmt, clippy.

### OI-04 — #872 and #873: the credential-superseded rule · Sonnet 5.5

**Where.** `crates/axiam-core/src/models/user.rs`
(`credential_changed_since_claims`, `credential_superseded`,
`versionless_artefact_uses_the_timestamp_rule`);
`crates/axiam-auth/tests/auth_service_test.rs` (the two `qr2_6_*` tests);
`crates/axiam-api-rest/src/handlers/opaque.rs` (`opaque_login_finish`);
`crates/axiam-api-rest/tests/opaque_login_test.rs`.

**Do.**
1. #872: in each `qr2_6_*` test, also assert that the `without_version` copy is
   **accepted** when the epoch is the start of the token's `iat` second. In the
   unit test, make the "strictly after" case consistent
   (`iat_secs = epoch.timestamp()`, `iat_ns = epoch_ns + 1`) and add the
   same-second, after-epoch, `Some(ns)` case that must not be refused. Prove the
   tests have teeth: temporarily switch the comparison to whole seconds, see
   them fail, restore. Record that in the `EXECUTED` block.
2. #873: add `User::credential_superseded_at(issued_at: DateTime<Utc>,
   version: Option<i64>)` (or a `DateTime`-based core that
   `credential_superseded` delegates to) and call it from `opaque_login_finish`
   in place of the inline rule. One rule, five callers.
3. #873 test: in `opaque_login_test.rs`, start a login, move
   `credential_changed_at` to now + 1 h **without** bumping the version, and
   assert that finish returns 200. Confirm it fails against the old `||` rule
   (temporarily reintroduce it, then restore).

**Verify.** `cargo test -p axiam-core --lib user`, `-p axiam-auth --test
auth_service_test`, `-p axiam-api-rest --test opaque_login_test`, fmt, clippy.

### OI-05 — #880, #881, #883: logout-token `kid`, CONTRACT 1.69, cross-SDK rules · Opus 5.5

**Why Opus.** It amends the normative contract that eleven repositories port,
changes a signed token's header, and needs a short security argument (below).
**Confirm D-1 with the owner before starting.**

**Part 1 — the server emits `kid` on logout tokens (#880, D-1).**
1. Test first, in the `axiam-oauth2` logout tests: decode the header of a minted
   logout token and assert `kid` equals the `kid` published at `/oauth2/jwks`
   for the signing key, and `typ` is still `logout+jwt`. Add a test that
   verifies the token the way a relying party does: fetch the JWKS, select the
   key **by `kid`**, verify. Both fail today.
2. In `crates/axiam-oauth2/src/logout.rs`, set the header `kid` from the same
   derivation the access and ID tokens use (`ed25519_jwk_kid` in
   `crates/axiam-auth/src/token.rs`). Prefer exposing one signer in `token.rs`
   over a second copy of the header logic; `sign_purpose_token` must keep
   refusing to add a `kid`.
3. **Security argument, written into the `EXECUTED` block and the threat
   model.** With a `kid`, the logout token is the only non-access token that a
   strictly-by-`kid` verifier can find a key for. Show, for the access-token
   path of the server (REST, gRPC, AMQP) and of the SDKs at contract 1.68, that
   a logout token is refused: by `typ` (rule 10), and independently by the
   claims an access token must carry and a logout token lacks. Then say what a
   **pre-1.68 SDK** (no rule 10) does with it and whether the claim-shape
   refusal alone holds there. If it does not hold for some SDK version, stop and
   report to the owner before committing; the alternative of D-1 then applies.
4. Add a pin test on the server: a logout token presented as a bearer access
   token is refused on REST and gRPC.

**Part 2 — CONTRACT 1.69.** Add `§34.13 Contract 1.69` in the form of §34.12 and
amend the places that say "no `kid`" for the logout token: §10.1 rule 12 and its
"Scope" paragraph, §12.7.3 rule 1, the token table of §34.11 (leave the
historical row, add the 1.69 change). State normatively:
- from 1.69 the logout token carries the `kid` of its JWKS key;
- an SDK's `verify_logout_token` selects the key by `kid`, refuses a kid-less
  token as `unknown_kid`, and follows §12.4 rule 2 for an unknown one;
- an SDK's logout test suite MUST include a **server-shaped** token: header
  exactly `{alg: EdDSA, typ: logout+jwt, kid}`, verified against a JWKS with
  **two** keys;
- rules 10 and 11 of §10.1 still do not apply on this path.

Then regenerate what derives from the contract: `website` (`npm run
gen:contract-anchors`), and check `python3 scripts/check-spec-digest.py` is
unaffected. Add the upgrade note to `docs/deployment/README.md`: relying
parties that verify logout tokens need nothing; an SDK-based RP could never
verify one before this release.

**Part 3 — Appendix A of this document (#881, #883).** Read the SA-15 server
code (the authz response producer in `axiam-amqp`) and write Appendix A, which
the seven AMQP SDK tasks copy from:
- **A.1 (#881, D-2):** the exact conditions under which a 1.68+ server sends an
  **unsigned** response to a `reply_to` queue, if any; the resulting canonical
  paragraph for the SDK READMEs and doc comments ("requires a server of 1.68 or
  later; a pre-1.68 server ignores `reply_to` …; the opt-out exists for …"); or
  the verdict "remove the opt-out" with the evidence.
- **A.2 (#883):** the canonical security event for a discarded response: the
  field names and meaning (timestamp, exchange, routing key = the reply queue
  name, tenant context, the discard reason) and what must never appear (a
  signature value, a nonce, the body). If CONTRACT §8 protocol rule 4 leaves the
  requester case ambiguous, make it explicit in the 1.69 text.

**Verify.** `cargo test -p axiam-oauth2` (the logout test file), the REST and
gRPC pin tests, fmt, clippy; `npm run gen:contract-anchors` leaves no diff after
a second run.

### OI-06 — #874, #879, #890, #891: documentation and comments · Sonnet 5.5

**Why Sonnet.** Sixteen small corrections, each specified by its issue. The
risk is a corrected sentence that is still wrong, so each one is checked against
the code (§1.2) and the `EXECUTED` block lists the symbol it was checked against.

**Do, issue by issue (the issue bodies give the line anchors):**
- **#874:** the SA-06 paragraph of `docs/deployment/README.md`: a current
  artefact is refused by its credential version; the timestamp comparison
  applies only to artefacts minted without one.
- **#879:** (1) the internal-queue sentence: restrict "must not grant" to
  consume (read) access; (2) the two comment blocks in
  `crates/axiam-api-rest/src/handlers/auth.rs`: the service refuses first, the
  handler check is a backstop.
- **#890:** (1) the `reset_mfa` comment in `crates/axiam-auth/src/mfa_methods.rs`;
  (2) the gRPC cap-test wording in `grpc_server_test.rs`, and pass an
  already-bound listener to the server instead of bind-drop-rebind if the test
  harness allows it without a production change; (3) the CSRF banner
  (`CSRF_EXEMPT_PATHS`, exact match) and the four test comments that say `sid`
  where the token carries `jti`.
- **#891, items 1–7:** as listed in the issue. Item 1 changes T-510 in
  `claude_dev/threat-model-stride.md` **and** `Axiam.json`, then regenerates
  `website/src/threatModel.ts` (`npm run gen:threat-model` in `website/`).
  Item 5 edits the *executed* audit plan (swapped test counts); item 6 the
  2.47.0 summary of the threat model. After OI-02 and OI-05, also add their
  threat-model lines here (the provisioning-before-admission fix; the logout
  `kid`) so the threat model is touched once.

**Verify.** `cargo test -p axiam-api-grpc --test grpc_server_test` (only if item
#890-2 changed the test), fmt for touched crates, `npm run build` in `website/`
if `threatModel.ts` changed, and the docs link check the repository's CI runs.

### OI-07 — #561: runs 6, 6b and 6c in the comparison documents · Sonnet 5.5

**State found on 2026-11-26.** The issue text is older than the runs. What
actually happened differs from it in five ways, and the task follows the runs,
not the issue:

| The issue says | What was run (seventh draft, §0) |
|---|---|
| Run 6 on the G-box (laptop), run-5 caps | Runs **6, 6b and 6c** on one cloud VM (AMD EPYC Genoa, 16 vCPUs, 64 GiB), 2026-11-20 to 2026-11-24 |
| AXIAM `1.0.0-beta18` | AXIAM **1.3.0** (run 6) and **1.3.1** (runs 6b, 6c) |
| Keycloak 26.8.0, Zitadel v4.19.4, authentik 2026.8.3 | **Keycloak 26.8.1, Zitadel v4.19.5, authentik 2026.8.5** |
| One run | Run 6 is the run of record (2 CPU caps, three profiles). Run 6b repeats plaintext at 4 CPUs. Run 6c repeats it on SurrealDB 3.3.5 (unsupported, benchmark-only) to size the SurrealDB 4.0.1 cost |
| authentik gets a performance statement | **No authentik cell passed the validity gate.** Only its resting footprint is a valid figure |

Already done, by the maintainer: the seventh draft of
`benchmarks/PUBLIC_BENCH_ANALYSIS.md` (commit `502534d`) and the website's
benchmark page (`360423e`, `1727af5`, `e85da89`, `9e1df52`). **Still open:** the
three comparison documents, which cite run-5 figures and say run 6 "will
measure … on the same G-box"; and one stale sentence on the website.

**The reading rules of the seventh draft are binding on every sentence written:**

1. **Run 6 is not comparable with run 5** (host, engine and release all
   changed). No run-5 figure stays next to a run-6 one as a trend, and the
   run-5 multiples (about 8× Keycloak and 6.5× Zitadel on client credentials,
   2.4× and 4.8× on introspection, RSS "under 8% of Keycloak's") are
   **replaced**, not kept.
2. **Head-to-head claims use run 6 (2/2) and run 6b pass B (4/4) only**, both
   on SurrealDB 4.0.1. Run 6c never enters a head-to-head sentence or table; it
   may be cited only as what it is, the size of the SurrealDB 4.0.1 regression
   (13–38% of AXIAM's throughput at 2 CPUs, 8–37% at 4).
3. Every figure names its run and the versions measured.
4. Rows that failed the validity gate are never part of a claim: all of
   authentik's, and Zitadel's login and fallback refresh.

**Do.**
1. **`claude_dev/competitor-comparison-keycloak.md`.** Rewrite the header note
   (lines about run 5 / run 6 / G-box), the summary paragraph, the *Server RSS*
   row and the "Efficiency is the product" point from the seventh draft:
   - token issuance 3.8–3.9× at 2 CPUs and 3.5–4.6× at 4 (the range covers
     Keycloak and Zitadel; take Keycloak's own figure from §1); JWKS 7.9×;
     login on par (§1, §13);
   - **Keycloak wins introspection and REST userinfo** head to head, and on
     whole-stack CPU per request (§1, §7). This goes in the summary, not in a
     footnote;
   - server RSS, run 6: AXIAM 54–75 MiB, Keycloak 708–941 MiB (§7); at 4/4,
     89–133 MiB against 1,082–1,170 MiB;
   - the memory claim of Keycloak 26.8: **no reduction observed** against run
     5's 710–853 MiB, stated exactly as §7 states it ("a different host, so a
     direction, not a measurement of its release-note claim");
   - AXIAM is database-bound on every data cell (§5).
2. **`claude_dev/competitor-comparison-zitadel.md`.** Same treatment: the
   header note, the *Server RSS* row (AXIAM 54–75 MiB, Zitadel 127–137 MiB),
   the *Whole-stack RSS* row and the "Data-plane performance" point (take
   Zitadel's multiples from §1; JWKS 21×, gRPC userinfo 12.6–28×). The resting
   footprint needs care: by resident set AXIAM's stack is smaller (373 MiB
   against 593 MiB), **by cgroup working set Zitadel's is** (172 MiB against
   216 MiB). Write both, as §7 does. The minimal-profile figures (207 MiB) were
   **not** re-measured: keep them labelled as the 2026-10-05 measurement.
3. **`claude_dev/competitor-comparison-authentik.md`.** Replace the "run 6 will
   measure it" paragraph. The honest statement is: authentik 2026.8.5 was run as
   a fourth target; **none of its cells passed the validity gate, so no
   throughput or latency comparison is made**; the only valid figure is the
   resting footprint (1,668 MiB whole stack: server 983, worker 347, PostgreSQL
   338, against AXIAM's 373 MiB). Say what the draft's next round plans for it
   (§13 item 7). This is weaker than the acceptance text of #561 ("so that the
   authentik comparison can make a performance statement"); record that gap in
   the `EXECUTED` block and in the closing comment, do not paper over it.
4. Each of the three documents gets a **dated change-log line** naming runs 6,
   6b and 6c, the versions measured and the fact that the run-5 figures were
   replaced.
5. **Website.** The page already carries the three runs. Fix the stale sentence
   near `website/src/pages/Benchmarks.tsx:1782` ("is still the run-5 analysis
   until its seventh draft is written"): the seventh draft exists. Then
   spot-check ten figures on the page against the draft (two per section) and
   list them in the `EXECUTED` block; correct any mismatch in favour of the
   draft.
6. **Copy numbers, do not summarise them.** Every figure written must be
   findable verbatim in the seventh draft, cited to its section. No rounding in
   AXIAM's favour. Also grep the repository (`README.md`, `docs/`, `website/`)
   for the run-5 multiples named in rule 1 and correct any that survive outside
   a context explicitly labelled run 5.
7. **Close the loop on the issue's binding notes.** The minimal profile, the
   production rate limits and the new-feature cells were **not** measured in
   this round (draft §9, §13 item 6). Say so in the closing comment on #561
   rather than implying the W5 F4 conditions were exercised.

**Verify.** `npm run build` and the website tests in `website/`;
`docSectionsAreComplete()` still passes; the markdown link check the
repository's CI runs. This task closes #561, with a closing comment that lists
where the outcome differs from the issue's acceptance text (versions, host, no
valid authentik cell).

---

## 5. Wave B — SDKs

### 5.0 Before Wave B: re-vendor the contract

OI-05 changes `sdks/CONTRACT.md`. Every SDK vendors a byte-identical copy of
`CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/`. The
orchestrator copies the new `CONTRACT.md` (and anything else that changed) into
each SDK working tree before its task starts; each SDK task verifies the copies
with `cmp` and commits them as part of its own commit. If an SDK has a
generation check tied to the vendored files (for example
`scripts/gen_management.py --check` in Java), run it.

### 5.1 Common work, by cross-SDK issue

| Issue | Which SDKs | What each does |
|---|---|---|
| #880 | all eleven that ship `verify_logout_token` (a task whose SDK has none says so and pins nothing) | Follow CONTRACT 1.69: select by `kid`, refuse kid-less. Add the server-shaped test (header exactly `alg`, `typ: logout+jwt`, `kid`; a two-key JWKS; the fixture signer must not add anything the server does not send). Add a test that rules 10 and 11 stay off the logout and ID-token paths. Update the README's contract-conformance line to 1.69. |
| #881 | TypeScript, Python, PHP, C#, Java, Go, Rust | Replace the opt-out documentation with Appendix A.1, in the README, the changelog and the doc comment of the option. If A.1's verdict is "remove", remove the option and its tests. |
| #882 | Go, Python, C#, PHP: fix. TypeScript, Java, Rust: pin | Fix: verify the HMAC over the received bytes and hand the handler a value parsed from those same bytes (D-5). Tests: a genuine message whose fields contain `<`, `>`, `&`, a non-ASCII character and a `\u` escape verifies; a body with a duplicate key or trailing content is nacked and the handler never runs. Pin: the same tests, expected to pass already; if one fails, it is a finding to fix. |
| #883 | Python, PHP, Java, Go, Rust: fix. TypeScript, C#: verify, fix if missing | Emit the Appendix A.2 event on every discard path of the requester. Extend the log tests to assert the routing key and the tenant are present and that no signature or nonce value is. |

### 5.2 Tasks

Every SDK task: read the issue in full, resolve **every** finding ID in the
table of §0, do the §5.1 work that applies, run the repository's CI commands,
write the changelog entry, one signed commit. The notes below add only what the
issue does not settle.

**OI-10 — `axiam-typescript-sdk` (#167) · Sonnet 5.5.** TYP-R3-1: percent-encode
the `Location` value in the Fastify redirect branch, with a test using a
`returnTo` that contains a space, a non-ASCII character and a CR/LF attempt.
Then **record the rule in `docs/login-glue-binding.md`** (the redirect target is
encoded by the adapter, never by the application hook), since OI-11 to OI-15
check their ports against it. TYP-R3-2 and the "Nits" section as written. #883
was fixed here in round 2: verify it against Appendix A.2 and align the field
names if they differ.

**OI-11 — `axiam-python-sdk` (#110) · Sonnet 5.5.** PYT-R1-2 is the one with
weight: an unexpected exception in `_handle` must fail the pending request and
keep the requester alive (or close it loudly and fail every later call), never
shut it down silently; test with a handler-internal exception. PYT-R1-4: decide
between restoring propagation to the application's exception handlers and
keeping the cookie-clearing guarantee by the rule in `login-glue-binding.md`;
the cookie clear wins, and the README states the deviation. PYT-R1-5: exclude
`binding_digest` from the repr. GLUE-R1-4 and GLUE-R1-5 as listed at the end of
the issue. #882: `verify_hmac` must stop re-serializing.

**OI-12 — `axiam-php-sdk` (#92) · Sonnet 5.5.** PHP-R1-1: make `#[RequireScope]`
repeatable (`Attribute::IS_REPEATABLE`) with all-must-pass semantics and a test
with two scopes. PHP-R1-2 with GLUE-R1-5: clear the binding cookie on every exit
of the callback, including a throwing `$onSuccess`. PHP-R1-4: refuse non-finite
and non-positive timeouts at construction and per call. PHP-R1-5: restore the
lost `\u` escapes so the two tests test what their names say (check they fail if
the verification is broken). PHP-R1-6 and PHP-R1-7 are documentation. #882:
`Consumer` / `Hmac::verify()`.

**OI-13 — `axiam-csharp-sdk` (#125) · Sonnet 5.5.** CSH-R5-1: correct the "a
throw aborts the sign-in" wording to what `Response.Clear()` guarantees.
CSH-R5-2: an `OperationCanceledException` that is not the client's abort must
take the same catch (clear the cookie, write the 500); test with a hook that
throws it while `RequestAborted` is not cancelled. #882: `Amqp/Hmac.cs`. #883:
check the discard log against Appendix A.2.

**OI-14 — `axiam-java-sdk` (#133) · Sonnet 5.5.** JAV-R1-1 is security-relevant:
`AxiamUser.roles` must come from the `roles` claim only, never from `scope`;
rewrite any fixture that expected the old mapping. JAV-R1-2: an unparseable
`returnTo` falls back to the default target, still clears the cookie, never a
500. JAV-R1-3 (D-4): the cooldown also holds on a cold cache and when the JWKS
endpoint fails. JAV-R1-6: complete decisions off the RabbitMQ consumer thread
(an executor the caller may supply) and document it. JAV-R1-8 with PYT-R1-5's
approach: keep the digest out of `toString()`. #882: pin only (fixed in SA-24).

**OI-15 — `axiam-kotlin-sdk` (#99) · Sonnet 5.5.** KOT-R1-1: add
`@AxiamRequireScope` and its `enforce` support, repeatable. KOT-R1-2: narrow the
two new public `JwksVerifier` members to what the contract allows (internal, or
`@RequiresOptIn`), since 1.4.0 is unreleased. KOT-R1-3: restore binary
compatibility with 1.3.1 for the changed public constructors (secondary
constructors or `@JvmOverloads`), and run the binary-compatibility check if the
build has one; correct the migration note either way. KOT-R1-4 with the GLUE
items: cookie clearing covers the paths where the hook throws or responds.
KOT-R1-5 (D-4). KOT-R1-7: enforce the store bound under the lock. No AMQP work.

**OI-16 — `axiam-go-sdk` (#111) · Opus 5.5.** GO-R1-1: fold keys exactly as
`encoding/json` does (the minimum of the `unicode.SimpleFold` orbit); test with
`ſubject_id` and a Kelvin-sign key; the same check serves `authz_requester.go`.
GO-R1-2 (D-4): cooldown around the forced `Refresh`, with the fifty-unknown-kid
test and the rotation half. GO-R1-3: `["admin", null]` is not an array of
strings. GO-R1-4: `Close` cancels the broker consumer with a known tag and the
adapter goroutine exits; prove it with a goroutine-leak assertion. GO-R1-5,
GO-R1-6, GO-R1-9: documentation, including README rows for rules 10–12 and the
snapshot nature of `roles`. GO-R1-7, GO-R1-8: test strength and the
single-space split. #882: `amqp/hmac.go` `verifyHMAC` must stop re-marshalling;
the event consumer follows the requester's pattern. #881 and #883: Go is the
reference the other six read, so apply Appendix A literally and report any place
where A does not fit the code back to the orchestrator before the others port
it.

**OI-17 — `axiam-rust-sdk` (#152) · Sonnet 5.5.** RUS-R1-1 and RUS-R1-2 together:
`AxiamUser` keeps an absent `roles` claim distinct from `[]` (an `Option`), and
a malformed `roles` claim no longer fails token verification with 401; it makes
`require_role` answer 403, as §11.2 rule 11(b) says. RUS-R1-3: `#[require_scope]`
stacks. RUS-R1-7: split on single spaces. RUS-R1-8: the requester's error kinds
and publisher-confirm handling as the issue describes. RUS-R1-5, RUS-R1-6:
documentation and the migration note (the new public field on `token::Claims`).
RUS-R1-9: the stray blank lines. Style: clear and concise Rust, no new
dependencies. #882: pin only.

**OI-18 — `axiam-cplusplus-sdk` (#89) · Sonnet 5.5.** D-3: implement §11.2 rule
11(b) (`require_role` refuses a `roles` claim that is not an array of strings,
`["admin", 7]` and `["admin", null]` included; `AxiamUser` keeps absent distinct
from empty), add `require_scope` (11(d), single-space split, the
`administrator` / `admin` test), document 11(e). If this changes the ABI, the
SOVERSION is already 6 for the unreleased 1.4.0; do not bump it again, but say
so in the changelog. Remove the README carve-out. CPL-R5-1: delete the changelog
bullet about the never-shipped test defect.

**OI-19 — `axiam-c-sdk` (#87) · Sonnet 5.5.** C-R3-1: narrow the "not retried"
claim to what the code does and add the missing test for the management
no-retry branch. C-R3-2: stop buffering a body the SDK will discard: enforce
`max_response_bytes` while reading (abort the transfer), with a test that a body
over the cap is refused without being held in memory. C-R3-3: move the
narrowing refusal before the nonce is claimed and make it independent of
`out != NULL`. Run the sanitizer build if the repository's CI has one.

**OI-20 — `axiam-swift-sdk` (#91) · Sonnet 5.5.** SWI-R1-1: rule 11 must refuse
`purpose: null` (inspect the raw payload for the key, not a decoded optional).
SWI-R1-4 and SWI-R1-5: the missing pins, and `assertRefused` checks the reason.
SWI-R1-2, SWI-R1-3: README to contract 1.69 and the changelog entry for
`AuditLogEntry.organizationID`. **O-1 (D-4):** implement the unknown-`kid`
re-fetch with cooldown in `JwksVerifier` and correct the doc comment that claims
it exists. **O-2:** covered by #880. **O-3 (D-3):** keep absent `roles` distinct
from `[]`, add `requireScope`. The sandbox has no Xcode: build and test with
`swift build` / `swift test` on Linux if the toolchain is present; if it is not,
say so plainly in the `EXECUTED` block and rely on the repository's CI after the
push. Do not claim a test run that did not happen.

---

## 6. Wave C — close-out

### OI-30 — consistency, regression, pull requests · Sonnet 5.5

1. **Vendored files.** In all eleven SDKs, `cmp` `CONTRACT.md`, `openapi.json`,
   `management-registry.json` and `diff -r proto/` against `axiam`. Zero
   differences.
2. **Cross-SDK consistency.** One table in this document: for #880–#883, the
   file and test that implements each in each SDK. An empty cell is a defect.
3. **Server regression.** After a `cargo clean`: the test files touched by
   Wave A, then `just check` scoped as `CLAUDE.md` allows on the sandbox disk;
   `python3 scripts/check-crate-layering.py`;
   `python3 scripts/gen-management-registry.py --check`.
4. **Changelogs.** Server `CHANGELOG.md` `[Unreleased]`: a Security entry
   (OI-01 to OI-03), a Changed entry (logout-token `kid`, contract 1.69), Fixed
   and Documentation entries. Each SDK: its `[Unreleased]` section.
5. **This document.** Every `EXECUTED` block present; the gate records present;
   the status line at the top changed to `EXECUTED (<date>)`.
6. **Pull requests** (the start prompt authorises them): one per repository,
   per §1.3. The server PR body links the eleven SDK PRs and states the merge
   order. Subscribe to each PR's activity. Do not merge.
7. **Issue #513:** add one comment stating that every code task is done and the
   submission (signed Certification of Conformance) is the maintainer's step,
   with a pointer to `claude_dev/fapi-certification-submission.md` step 4. Leave
   it open.

---

## 7. Out of scope

- **#513, the OpenID Foundation submission.** It needs a declaration signed by
  an authorised representative. No agent can do it (D-7).
- **Releases.** No version bump, no tag, no publishing, in any repository. The
  owner cuts server 1.3.2 (or 1.4.0) and SDK 1.4.0 after the merges.
- **Pull request #893.** Another session owns it.
- **New review findings beyond §1.6.** The gate is bounded on purpose.
- **Benchmarks.** No new run. OI-07 only transcribes runs 6, 6b and 6c from the
  seventh draft; the passes that draft defers (§13) stay deferred.

---

## Appendix A — cross-SDK rules (written by OI-05)

> **A.1 — the unsigned-response opt-out (#881).** *To be written by OI-05.*
>
> **A.2 — the discarded-response security event (#883).** *To be written by
> OI-05.*
