# Release 1.1.0 plan — the 1.0.1 review findings, contract 1.62 and RADIUS D4

> **Status: READY — D-1 … D-6 answered 2026-10-14 (§11).** Written against `main` at `c6eebd1` (after
> release 1.0.1, ilpanich/axiam#657, and the dependabot merges that followed).
> It covers **43 of the 45 open issues** on `ilpanich/axiam`: the forty-two Low
> and Informational findings the 1.0.1 reviews filed on `1.0.x` (#615 … #656,
> #653 included) and the last deliverable of the RADIUS tracker, **#563 D4**
> (the `rlm_rest` authorize endpoint). **#513** (the certification submissions)
> and **#561** (benchmark run 6) stay the maintainer's and are out of scope
> (§0.3 lists what each still needs from the maintainer).
>
> **Why 1.1.0 and not 1.0.2.** D4 is a new authenticated API surface with its
> own data model (network segments, reply profiles), its own permissions and a
> new contract section. That is a feature, so the platform release is **1.1.0**.
> If D4 slips (decision D-1), W1 … W5, W7 and W8 ship on their own as **1.0.2**
> with no other change to this plan: W6 is the only wave that adds routes.
>
> **Shape.** Eight waves. W1 … W6 are independent and branch from `main`; W7
> (contract 1.62, the eleven SDK re-syncs and the SDK fixes decided on
> 2026-10-14) needs every wave that changes the spec; W8 (release readiness)
> needs everything. As for 1.0.0 and 1.0.1, the waves merge into one plan
> branch, `claude/release-1.1.0`, and **one pull request** closes every issue
> on a `Closes` line. The eleven SDK repositories get one pull request each.
>
> **Execution.** One **Opus 5.5 orchestrator** session runs the plan. It
> spawns one executor per task at the model its row names, runs the gate of
> §10 before every commit, and ends each wave with an F4 security review of
> the wave diff (Opus 5.5). The orchestrator writes code only to resolve a
> merge; everything else is an executor's. Every commit is signed; nothing is
> closed by hand.
>
> **What the agent does not do.** It does not tag, does not merge, does not
> run the conformance suites, does not dispatch benchmark runs, and does not
> answer a contract question on its own: every question is in §12, answered.

---

## 0. The state, measured (2026-10-14)

Verified on the tree, not taken from the issues. Where an issue and the tree
disagree, the tree wins and the task says so.

| Fact | Measured | Evidence |
|---|---|---|
| Platform version | `1.0.1` in the tree; **no `v1.0.0` or `v1.0.1` tag on `origin`** (latest is `v1.0.0-beta18`) | `Cargo.toml:62`; `git ls-remote --tags origin` |
| CHANGELOG | `## [Unreleased]` empty; `## [1.0.1] - 2026-10-14` | `CHANGELOG.md:8-10` |
| Contract | **1.61**; its record is **§34.5**; highest section **§35** (CRL, informative); next free top-level section **§36**; next record **§34.6** | `sdks/CONTRACT.md:12611,12660` |
| Threat model | **2.41.0**, `threatTop` 477; next free id **T-478**; T-450 and T-462 **Open** for the FreeRADIUS recipe (kept, D-9 of #657 answered "keep") | `ThreatDragonModels/Axiam/Axiam.json`; `claude_dev/threat-model-stride.md:10,4409-4429` |
| Schema | newest migration **v98** (`certificate.user_id`); next **v99**; the newest-version assertion must be bumped with each | `crates/axiam-db/src/schema.rs:4938,6442` |
| SDKs | the eleven contract-1.61 PRs are **merged** (e.g. ilpanich/axiam-java-sdk#113, 2026-10-14); none is tagged; four of them (Rust, Java, Kotlin, PHP) record a source-breaking change in their 1.0.1 notes | each SDK's `CHANGELOG.md`, `[1.0.1]` |
| RADIUS | option B recipe shipped (`docs/pki/freeradius.md`, `docker/docker-compose.radius.yml`, `radius-e2e.yml`, `crates/axiam-server/tests/radius_e2e.rs`); `network:*` permissions and the segment/profile model are **not in the tree** | `crates/axiam-api-rest/src/permissions.rs` (no `network:` row); `claude_dev/radius-reply-profile-design.md` §2 |
| Open issues | 45; 43 in scope | GitHub, 2026-10-14 |
| Open PRs | one dependabot PR (#662); nothing of this plan's is open | GitHub |

### 0.1 Where the issues and the tree disagree

| # | What the issue says | What the tree says | Consequence |
|---|---|---|---|
| 626 | `[Unreleased]` misses #590 and #594 | `## [1.0.1]` carries one entry each (`CHANGELOG.md:587,603`), written by 1.0.1's W7.4 as the issue's own orchestrator note predicted | **No code.** On the `Closes` line with a one-line comment naming the two entries (W4.1) |
| 629 | three deployment files and `operate.ts:122` omit the outbound and cleanup steps and say 5 s for the lease-loss drain | all four now list the five steps (`20 + 5 + 2 + 5 + 5 = 37 s`), name `ORDERLY_STOP` / `LEASE_LOSS_STOP` and say 3 s (`docker-compose.minimal.yml:193-196`, `docker-compose.prod.yml:318-323`, `k8s/server/deployment.yml:21-26`, `operate.ts:122`); 1.0.1's W7.3 took it | **No code.** On the `Closes` line with a comment naming W7.3 (W4.1) |
| 636 | asks for a CHANGELOG upgrade note **and** a 422 refusal of outside scopes on a non-`admin` row | the note is in `## [1.0.1]` (`CHANGELOG.md:21`); the refusal is not | only the refusal (and its test) is W3.2 |
| 642(d) | `boot.rs:2766` has `)),` at column 0 | now `boot.rs:2783` | none |
| 621(a) | `docs/admin/README.md:254` | now `:259` ("kept … until it expires"); `operate.ts:1095` says the same | none |
| 621(c) | `KEPT_REVOCATION` in `tenant_purge.rs:140` | there is no `tenant_purge.rs` under `crates/axiam-server/src`; the executor finds the constant (`rg KEPT_REVOCATION crates/`) and records the path in the commit body | none |
| 631 | "proposed fix (W5): the SDKs' stream-update helpers send what they read" | 1.0.1's W5 did exactly that in all eleven SDKs (`SsfStreamInput::from(&SsfStream)` and its ten siblings send `events_requested` and `expected_updated_at` as read); what remains is Q2's change-taking form, decided on 2026-10-14 (§12) | the issue closes with W7.2's helper; the API-client half is contract text (W7.1) |
| 656 | "name the per-address backstop in the contract's next record" | the backstop exists (`server.rs:844-852`); only text is missing | W7.1 text, plus the OpenAPI response description on the route (W3.8 regenerates) |

### 0.2 What this plan could not do

- **SAGE** is not connected in the writing session (`sage_inception` is not
  among the session's tools); the plan is built from the repository, the
  issues, PR #657 and the maintainer's answers of 2026-10-14 alone.
- **Milestones** cannot be set from the session's tooling. The forty-two
  findings are on `1.0.x`; the maintainer creates **`1.1.0`** (or `1.0.2`,
  D-1) and moves the 43 issues when the plan starts.
- **Tags.** PR #657's hand-off (its steps 2 … 5) has not run: nothing is tagged.
  This plan assumes `v1.0.1` and the eleven SDK tags (**1.1.0** for Rust, Java,
  Kotlin and PHP; **1.0.1** for the other seven — Q5, §12) are pushed **before
  W7 starts**, so that each SDK's 1.62 change log has a released version to
  follow (D-2).

### 0.3 Out of scope, and what each needs from the maintainer

| # | Item | What it waits for |
|---|---|---|
| 513 | OpenID Basic OP and FAPI 2.0 submissions | the maintainer's runs against the 1.0.1 release and the X5.3 submission; T23.1.4 … T23.1.7 are audits of code already in the tree (`claude_dev/fapi-certification-submission.md`) |
| 561 | Benchmark run 6 (W6b) | the G-box numbers from `claude_dev/run6-runbook.md` §12; W6b is one Sonnet 5.5 session once they exist (seventh draft, three comparison rows, `website/src/data.ts`) |
| 563, option A | the native RADIUS front end | the reopen condition of record §1.4; nothing here |

---

## 1. Scope — every open issue, one wave each

Severity is as filed. Size: S ≤ ½ session, M ≈ 1 session, L ≈ 2 sessions.

| # | Title (short) | Severity | Wave | Task | Size | Model |
|---|---|---|---|---|---|---|
| 615 | The CRL number can go down | Low | W1 | W1.1 | M | Opus 5.5 |
| 616 | The CRL route queues unauthenticated callers without bound | Low | W1 | W1.2 | S | Opus 5.5 |
| 617 | A failed key release makes a tenant CA's Vault forward permanently refused | Low | W1 | W1.3 | M | Sonnet 5.5 |
| 618 | An erased account's certificate rows keep personal data | Low | W1 | W1.4 | M | Sonnet 5.5 |
| 619 | Vault refusal text enters the audit log unsanitised | Informational | W1 | W1.5 | S | Sonnet 5.5 |
| 620 | The bootstrap Vault client in `main.rs` is not under test | Informational | W1 | W1.6 | S | Sonnet 5.5 |
| 621 | Text behind the code after W1.4 and W1.5 | Informational | W1 | W1.7 | S | Sonnet 5.5 |
| 622 | Small races and edges (a)–(d) | Informational | W1 | W1.8 | M | Opus 5.5 |
| 653 | Certificates on the same public key get the same serial | Low | W1 | W1.9 | S | Sonnet 5.5 |
| 651 | Ed25519 private keys as PKCS#8 v2 unreadable by OpenSSL 3.0 | Informational | W1 | W1.10 | S | Sonnet 5.5 |
| 649 | Certificate subjects accept control characters | Low | W1 | W1.11 | S | Sonnet 5.5 |
| 654 | SAML verifications wait without bound on the crypto semaphore | Low | W2 | W2.1 | S | Sonnet 5.5 |
| 632 | Two rate-limit buckets share a name with existing ones | Low | W2 | W2.2 | S | Sonnet 5.5 |
| 633 | Authenticated federation routes key their limiter on the address | Informational | W2 | W2.3 | M | Opus 5.5 |
| 634 | The IdP's self-checks parse with recovery on | Informational | W2 | W2.4 | S | Sonnet 5.5 |
| 635 | The device-code grant authenticates no client | Low (Medium on `fapi2`) | W3 | W3.1 | L | Opus 5.5 |
| 636 | The scope ceiling withholds administrator-added scopes | Informational | W3 | W3.2 | S | Sonnet 5.5 |
| 637 | A forged export receipt sets the purge bound | Low | W3 | W3.3 | M | Opus 5.5 |
| 638 | The CIBA hint cap's rows are never swept | Low | W3 | W3.4 | S | Sonnet 5.5 |
| 639 | The CIBA hint cap cannot be configured | Informational | W3 | W3.5 | S | Sonnet 5.5 |
| 640 | The export bound and the audit timestamps use two clocks | Informational | W3 | W3.6 | S | Sonnet 5.5 |
| 641 | Residual paths after the tombstoned-tenant client fix | Informational | W3 | W3.7 | M | Sonnet 5.5 |
| 642 | Text and hygiene after wave W3 (a)–(g) | Informational | W3 | W3.8 | S | Sonnet 5.5 |
| 655 | A cleanup cut holds a tenant purge for an hour or loses its record | Low | W4 | W4.2 | M | Opus 5.5 |
| 624 | A cut erasure loses its audit row for good | Low | W4 | W4.2 | (with 655) | Opus 5.5 |
| 625 | The GDPR dead letter's structured event can be skipped | Low | W4 | W4.3 | S | Sonnet 5.5 |
| 628 | The lease release is outside the stop budget; the REST cut is untested | Informational | W4 | W4.4 | M | Opus 5.5 |
| 623 | The conformance workflow's `module_timeout` reaches bash arithmetic | Low | W4 | W4.5 | S | Sonnet 5.5 |
| 630 | The unattended baseline's provenance; the gate's tolerant path | Informational | W4 | W4.6 | S | Sonnet 5.5 |
| 627 | Turning a surface back on under an organization `false` saves silently | Informational | W4 | W4.7 | S | Sonnet 5.5 |
| 626 | `[Unreleased]` misses #590 and #594 | Low | W4 | W4.1 | — (done in 1.0.1) | Sonnet 5.5 |
| 629 | Stale stop arithmetic outside the guide | Informational | W4 | W4.1 | — (done in 1.0.1) | Sonnet 5.5 |
| 643 | The fetch script's signature check does not stop a forged list | Low | W5 | W5.1 | M | Sonnet 5.5 |
| 644 | `ca_path_reload_interval` re-reads `ca_file`; a removed `ca.pem` keeps old trust | Low | W5 | W5.2 | S | Sonnet 5.5 |
| 645 | The revocation lag omits HTTP caching; the note states a different bound | Low | W5 | W5.2 | (with 644) | Sonnet 5.5 |
| 646 | RadSec client without `require_message_authenticator`; the NAS side | Low | W5 | W5.2 | (with 644) | Sonnet 5.5 |
| 647 | The re-encoding snippet leaves the private seed on disk | Low | W5 | W5.2 | (with 644) | Sonnet 5.5 |
| 648 | T-454's named test does not test "vendors nothing" | Low | W5 | W5.3 | S | Sonnet 5.5 |
| 650 | The radius-e2e path filter misses files the e2e depends on | Informational | W5 | W5.3 | (with 648) | Sonnet 5.5 |
| 652 | `Tunnel-Private-Group-Id` written without its tag | Informational | W5 | W5.4 | S | Sonnet 5.5 |
| 563 | RADIUS D4: the `rlm_rest` authorize endpoint | none, "D4 remains" | W6 | W6.1–W6.7 | XL | see §7 |
| 656 | Contract §33.3 rule 16 omits the per-address backstop; §27.15 note 10 stale | Informational | W7 | W7.1 | S | Sonnet 5.5 |
| 631 | API clients can still widen a narrowing | Informational | W7 | W7.1 + W7.2 | S + M | Sonnet 5.5 |

Out of scope, by decision: **#513**, **#561**.

### 1.1 How the model is chosen

The rule of the 1.0.1 plan, unchanged, so that the orchestrator can re-derive
it when a task turns out larger than sized. "Best but cheapest" means the
cheapest of the two that can be trusted with the row's *definition*, not with
its typing:

- **Opus 5.5** where the task *defines* behaviour under adversarial input or
  concurrency (a verifier, a parser, a lock, a sweep that two replicas run, a
  cancellation boundary), or where it spans a schema migration plus three or
  more crates, or where the issue proposes two designs and the executor has to
  choose on the evidence in the tree, or where it is a **new authenticated
  oracle** (W6.4). Every F4 review and the orchestrator are Opus 5.5.
- **Sonnet 5.5** where the issue already states the fix, the tree holds a
  precedent at a named `file:line`, and the oracle is a test the issue names.
  The guide and recipe fixes (W5), the SDK re-syncs (W7) and most text are of
  this kind.

Expected cost, counted in executor sessions: W1 8–9 (three Opus), W2 3 (one
Opus), W3 6–7 (two Opus), W4 5 (two Opus), W5 3 (none), W6 9–11 (four Opus),
W7 13–15 (none; eleven SDK sessions), W8 2–3 (two Opus). Roughly **49–56
sessions, 14 of them Opus**, plus the orchestrator. W6 is the long pole and
may be re-sized by its first session; W7 is wide, not deep, and its eleven
SDK sessions run in parallel.

---

## 2. Wave W1 — PKI, CRL, Vault and certificates (branch `claude/release-1.1.0-w1`)

**One of the two waves that touch `crates/axiam-db/src/schema.rs`.** Migrations
are numbered here so no other branch competes for a version: **v99** (W1.9,
only if no index on `(issuer, serial)` exists). W6 takes v100 … v102. Each
lands with a `vNN_adds_only_…` scope test and the newest-version bump, as v98
did (`schema.rs:4938,6442`). W1.1 and W1.2 share `crl.rs` and are one executor.

| Task | Issue | What lands | Where (on `main` @ `c6eebd1`) | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W1.1 | #615 | `list_identity` clamps `thisUpdate` to `epoch.end − 1 s` and each entry's stated date to `thisUpdate`, so a datastore clock ahead of the replica cannot push the number back or put `thisUpdate` in the future. The module doc, T-102 and `docs/pki/README.md` state the conditions under which monotonicity holds (interval unchanged, skew under half an epoch) and what an operator does when raising or lowering `AXIAM__PKI__CRL_NEXT_UPDATE_SECS` (the number may step; relying parties that cache by number re-fetch at `nextUpdate`). A per-CA persisted high-water number is **not** built unless the executor shows the clamp insufficient. | `crates/axiam-pki/src/crl.rs:709ff`; T-102 | `crl_test.rs`: a future `revoked_at` plus an entry expiring at the boundary — the number grows across the boundary and `thisUpdate < epoch end`; the existing determinism test (two services, one store, identical bytes) still passes | M | Opus 5.5 |
| W1.2 | #616 | `CrlService::current_at` bounds the wait for the per-CA `signing` mutex by `permit_wait` (`tokio::time::timeout` → `503`), and the per-CA flight is shared: waiters receive the in-flight outcome, a `503` included, rather than each starting its own 5 s. | `crl.rs:482ff`; the semaphore `boot.rs:688-698`; precedent for shared flight `crl.rs:259,319-367` (1.0.1 W1.3) | a new `crl_test.rs` case: eight concurrent requests under a held gate all answer within about `permit_wait` | S | Opus 5.5 |
| W1.3 | #617 | When a CA forward fails with Vault's "adding issuer to its own CRL is not allowed", `forward_pending_ca_revocations` retries the issuer deletion before the next forward (the sweep re-runs `store.delete` for the child, then forwards). T-470 and `docs/pki/README.md` name the single-mount dependency. Vault's `POST <mount>/issuer/<child>/revoke` is **not** adopted (it pins Vault ≥ 1.11; record it as the alternative in T-470). | `crates/axiam-pki/src/ca.rs:965-998`; the sweep in `cleanup.rs` (1.0.1 W1.5/W1.6); `vault_pki.rs:835-850` | `vault_pki_test.rs`, wiremock: issuer `DELETE` fails, `revoke` answers 400 with the issuer message; the next sweep re-deletes and then forwards | M | Sonnet 5.5 |
| W1.4 | #618 | The Art. 17 purge (step b4) also clears `metadata` on the account's certificate rows, as `tenant_purge` does. A new cleanup step deletes revoked or expired certificate rows more than eight days past `notAfter` in **live** tenants (the CRL no longer lists them; the eight days are `KEPT_REVOCATION`, W1.7(c)). `docs/compliance/gdpr-compliance.md` and T-187 restate the residual and the legal basis (Art. 6(1)(f) / Art. 32 for the security retention, not Art. 17(3)(b)). | `crates/axiam-server/src/cleanup.rs:1825-1830`; precedent: the tenant purge's `metadata` clear | `req14_gdpr_test.rs`: after the purge the rows carry `metadata = {}`; `cleanup_task.rs`: a row nine days past `notAfter` is deleted and the CRL is unchanged | M | Sonnet 5.5 |
| W1.5 | #619 | `sanitise_reason` is applied before the `ca_certificate.vault_revocation_pending` and `certificate.vault_revocation_pending` audit appends and before both `tracing::error!` calls; `looks_like_a_token` gains the `b.` prefix. | `crates/axiam-pki/src/vault_forward.rs:52-80`; `handlers/ca_certificates.rs:396`; `handlers/certificates.rs:491` | unit tests in `vault_forward.rs` (`b.` is masked); a handler test asserts the audit row's reason is the sanitised form | S | Sonnet 5.5 |
| W1.6 | #620 | The bootstrap client builder moves to `axiam_auth::secrets::bootstrap_client()` (used by `main.rs:148-155`), with a test that it surfaces a `307` rather than following it. | `crates/axiam-server/src/main.rs:148-155`; `crates/axiam-auth/src/secrets.rs`; precedent `vault_provider_test.rs` | `vault_provider_test.rs`: the provider built on `bootstrap_client()` sees the `307`; a second host sees nothing | S | Sonnet 5.5 |
| W1.7 | #621 | (a) `docs/admin/README.md:259` and `operate.ts:1095` say "eight days after it expires"; (b) `operate.ts:1186` says a row in backoff or past the threshold does not fail `vault_revocation`; (c) a test in `axiam-server` (which sees both crates) asserts `KEPT_REVOCATION ≥ MAX_CRL_NEXT_UPDATE_SECS + margin`. | the three files; `crates/axiam-pki/src/crl.rs:150` | the new assertion test; `scripts/check-doc-links.sh` | S | Sonnet 5.5 |
| W1.8 | #622 | (a) `purge_orphan` records `tenants.purged {orphan: true}` only when a step removed rows, or claims with a conditional marker; (b) `check_bound_user` re-checks the account after the create and revokes on create when it is gone; (c) `DELETE /api/v1/users/{unknown}` skips the revocation when the account was not found; (d) `record_vault_forward_failure` becomes `WHERE vault_next_attempt_at = $lease`. | `cleanup.rs` (orphan scan, 1.0.1 W1.7); `handlers/certificates.rs` (1.0.1 W1.8 `check_bound_user`); `handlers/users.rs:509ff`; the sweep's claim (1.0.1 W1.5) | `cleanup_task.rs`: two orphan scans over one store, one record; `certificate_test.rs`: deletion between check and create leaves no active certificate; `users` test: `404` revokes nothing | M | Opus 5.5 |
| W1.9 | #653 | Every issuance (leaf, CSR signing, CA) sets `CertificateParams::serial_number` to 20 CSPRNG bytes with the top bit cleared. **v99** adds a unique index on `(issuer, serial)` if none exists (the executor checks `schema.rs` first and skips the migration if the index is there; then no v99 and W6 still starts at v100). | `crates/axiam-pki/src/cert.rs` (the three `CertificateParams` sites), `ca.rs`; `schema.rs` | `certificate_test.rs`: the same CSR signed twice yields two serials; revoking one leaves the other off the CRL | S | Sonnet 5.5 |
| W1.10 | #651 | Ed25519 private keys are returned in RFC 8410 **version 1** form (seed only) by default; a `key_format` request choice is **not** added (one knob fewer). `docs/pki/freeradius.md` drops its re-encoding workaround (W5.2 reads this task's result) and `docs/pki/README.md` says which form is returned and why. OpenAPI description text regenerated in-wave. | `crates/axiam-pki/src/crypto.rs:84-90` (`to_pkcs8_pem`) | `crypto` unit test: the PEM parses with `openssl pkey` 3.0 semantics (assert the DER has no public-key attribute); `radius_e2e.rs:697-730` no longer needs to re-encode | S | Sonnet 5.5 |
| W1.11 | #649 | `subject_common_name` refuses any `char::is_control`, requires a printable subject of bounded length (64, RFC 5280 `ub-common-name`), and `docs/pki/README.md` recommends a device-name pattern. | `crates/axiam-pki/src/subject.rs:30-55` | unit tests: `\n`, `\t`, 65 characters → error; handler test: `400` | S | Sonnet 5.5 |
| W1.12 | — | F4 review of the W1 diff → `claude_dev/security-review-release-1.1.0-w1-<date>.md`. Medium and higher fixed in the wave; Low and Informational filed on the next patch milestone. | | | — | Opus 5.5 |

Closes: #615, #616, #617, #618, #619, #620, #621, #622, #649, #651, #653.

---

## 3. Wave W2 — SAML, federation and rate limiting (branch `claude/release-1.1.0-w2`)

Install `libxml2-dev` and `libxmlsec1-dev`; run the `build-no-saml` `cargo
check` before every commit as well as the gate.

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W2.1 | #654 | Each SAML acquire on the shared crypto semaphore is bounded by `hash_acquire_timeout_secs`; the timeout is that path's existing refusal (ACS: the invalid-response answer; IdP SSO/SLO: `503`). | `crates/axiam-federation/src/saml.rs:740-746`, `saml_metadata.rs:291-298`; `handlers/saml_idp.rs:640`, `saml_idp_slo.rs:467`; precedent `crl.rs:571-592`, `password_reset.rs:125-129` | with all permits held, an ACS post and an IdP SSO post return within the bound; a CRL re-sign queued behind them gets the next permit | S | Sonnet 5.5 |
| W2.2 | #632 | The two authenticated buckets are renamed `federation_link_saml_acs` and `federation_link_oidc_callback`; a test collects every endpoint name passed to `RateLimitShared` and fails on a duplicate. T-474, the CHANGELOG and the deployment docs are corrected ("each in a bucket of its own"). | `server.rs:467,561` and the #614 registrations | the duplicate-name test; the existing per-route limiter tests | S | Sonnet 5.5 |
| W2.3 | #633 | A `RateLimitKeyMode::Principal` keying on `(tenant, sub)` for the authenticated federation routes (`/federation/saml/acs`, `/metadata`, `/federation/oidc/authorize`, `/callback`, `/authn-request`), with the address as the pre-authentication fallback. The design decision (principal alone versus `(address, sub)`) is the executor's on the tree's evidence; the commit body says which and why. | the limiter (`crates/axiam-api-rest/src/rate_limit*.rs`), `server.rs:1391-1400,1816-1830` | one token from many addresses is bounded; a relay with many users is not throttled as one | M | Opus 5.5 |
| W2.4 | #634 | `saml_idp/sign.rs:181,276` use `receiver_parser_options()`. | the two sites | the existing IdP signing tests | S | Sonnet 5.5 |
| W2.5 | — | F4 review of the W2 diff. | | | — | Opus 5.5 |

Closes: #632, #633, #634, #654.

---

## 4. Wave W3 — OAuth2, CIBA and tenant lifecycle (branch `claude/release-1.1.0-w3`)

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W3.1 | #635 | The device-code grant authenticates its client: the poll requires `client_id` and refuses one that is not the grant's (`invalid_grant`); it reads the client (gone or no longer holding the grant → `invalid_client`); for a non-public client it runs `authenticate_client_credential` with the request context, `fapi::enforce_token_request` and the same token binding the other grants apply (`cnf` for DPoP and mTLS); `/oauth2/device_authorization` authenticates a non-public client too. The admin API keeps admitting the grant on any client (the full fix, not the registration-time refusal). T-289 amended. | `handlers/oauth2.rs:2141-2185`; `device_service.rs:274-439,348-352`; `oauth2_clients.rs:422-431`; the client-authentication path `token.rs:3184-3222` | a confidential client's grant needs its secret at the poll; a foreign `client_id` is `invalid_grant`; a DPoP-bound client's device token carries `cnf.jkt`; removing the grant type refuses an approved grant; the SDK device-flow fixtures still pass (public client) | L | Opus 5.5 |
| W3.2 | #636 | Admin `create` / `update` of a `managed_by: dcr\|cimd` row refuse (422, naming the scope) a scope outside the tenant's effective `dcr_allowed_scopes`. The CHANGELOG note is already in 1.0.1 (§0.1). | `oauth2_clients.rs:805-1015`; the ceiling from 1.0.1 W3.4 | the admin PUT of an outside scope on a DCR row is refused; on an `admin` row it is accepted | S | Sonnet 5.5 |
| W3.3 | #637 | `process_audit_event` refuses the server's control actions (`tenants.*`, `gdpr.*`) from AMQP; the purge bound is clamped to the named receipt's datastore `timestamp`; the deletion refuses a receipt whose `exported_through` is after its own timestamp. T-118 amended. | `audit_consumer.rs:177-186`; `handlers/tenants.rs:142-173`; the purge's bound (1.0.1 W3.5) | a reserved action from AMQP is not persisted; the bound never exceeds the receipt's timestamp; a future `exported_through` is refused at deletion | M | Opus 5.5 |
| W3.4 | #638 | `CibaHintCap::admit` reads the previous window with a `SELECT`; a cleanup step deletes `rate_limit_bucket` rows whose `updated_at` is older than twice the longest window in use. | `crates/axiam-oauth2/src/ciba.rs:912-937`; `cleanup.rs` | a new hint creates one row; the sweep removes stale rows and keeps current ones | S | Sonnet 5.5 |
| W3.5 | #639 | `RateLimitConfig::bc_authorize_per_hint` (env `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_HINT`, validated `>= 1`, default 3); refused calls are no longer counted (the two-window rule bounds admissions); `docs/conformance/` and the SDK integration-suite docs name the setting. `scripts/check-config-key-coverage.py` sees the new key. | `ciba.rs` constants; `config.rs`; `rate_limit` presets | config test (`0` refused, default 3); a fourth call with the knob at 4 is admitted | S | Sonnet 5.5 |
| W3.6 | #640 | The export takes `started_at` from the datastore (`RETURN time::now()`), so the bound and the rows' timestamps share one clock. | `handlers/tenants.rs:845`; `audit.rs:355` | a test with a skewed application clock exports every row at or before the bound | S | Sonnet 5.5 |
| W3.7 | #641 | (a) `DeviceAuthorizationService::authorize` reads the tenant (folded into W3.1's client read where possible); (b) the poll maps the tenant's `NotFound` to `invalid_grant`; (c) the tombstone transaction deletes `device_grant`; (d) the `sa_` `client_credentials` path answers a tombstoned tenant `invalid_client`. | `device_service.rs:348-352`; the tombstone transaction (1.0.1 W3.2); `token.rs:1636-1641` | tombstone then: no new user code, poll `invalid_grant`, no `device_grant` rows, `sa_` path `invalid_client` | M | Sonnet 5.5 |
| W3.8 | #642 | (a) `client_grants.rs` module doc, the #610(d) CHANGELOG entry and T-289 give R101W3-01 as the reason; (b) the OpenAPI text of `DELETE /api/v1/oauth2-clients/{id}` lists device grants and CIBA requests; (c) the CIBA grant skips the ID token when the ceiling removed `openid`; (d) `boot.rs:2783` re-indented; (e) the W3.2 quick-bench number of 1.0.1 is run and recorded in this plan's §13; (f) and (g) left as they are, recorded. This task also regenerates `sdks/openapi.json` (the (b) text and #656's route description, so W7 finds it done). | the files named | the OpenAPI drift job green; `token_ciba.rs` test: no ID token without `openid` | S | Sonnet 5.5 |
| W3.9 | — | F4 review of the W3 diff. | | | — | Opus 5.5 |

Closes: #635, #636, #637, #638, #639, #640, #641, #642.

---

## 5. Wave W4 — stop budget, durability, console and CI (branch `claude/release-1.1.0-w4`)

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W4.1 | #626, #629 | No code: one comment each on the issue, naming the 1.0.1 commits (W7.4's CHANGELOG entries; W7.3's stop-arithmetic text) and the lines in §0.1. Both go on the PR's `Closes` line. | — | — | — | Sonnet 5.5 |
| W4.2 | #655, #624 | One cancellation design for both: the cleanup task checks the stop **between** tenants and between users, and runs each unit of work that must end in an audit row (a tenant's purge through its `tenants.purged` record; a user's erasure through its `gdpr.user_pseudonymized` row and the `account_deletion` completion) as its own `tokio::spawn`ed task that `join_cleanup`'s abort does not cancel and that `join_cleanup` waits for within the stop's margin. The tenant purge claim is released from a drop guard on any other exit. T-444 and the guide's "What a stop can cut" list the cases. | `crates/axiam-server/src/boot.rs:3431-3450`; `cleanup.rs:263-370,1843-1894`; `docs/deployment/README.md:1847-1859` | `cleanup_task.rs`: a step hook holds the tick inside a tenant purge across a stop — the next start purges at once and `tenants.purged` exists exactly once; a tick held between anonymization and the audit row across a stop still leaves the `gdpr.user_pseudonymized` row | M | Opus 5.5 |
| W4.3 | #625 | `dead_letter_audit` emits the structured `axiam.audit.dlq` event before the file append; the file's own failure is logged separately. | `handlers/gdpr.rs:205-257` | a dead letter whose awaiting future is dropped during the file write still logs the event | S | Sonnet 5.5 |
| W4.4 | #628 | The `SIGTERM` teardown signals the cleanup task before the lease release and bounds the release (1 s, inside the margin). A `minimal_profile_boot.rs` case drives the lease-loss REST cut: a handler sleeps past the cut and the client's connection is closed at about 5 s while the audit drain still runs. | `boot.rs:3274-3290`; `tests/minimal_profile_boot.rs` | the new case; `a_lost_lease_cuts_the_requests_in_flight_before_the_backstop` still passes | M | Opus 5.5 |
| W4.5 | #623 | The workflow validates `module_timeout` (`^[0-9]{1,5}$`) and `plan_name` (`^[a-z0-9-]{1,128}$`) before use and fails otherwise; `run-plan.sh:120` and `run-some.sh:83` refuse a non-numeric value before the arithmetic. | `.github/workflows/fapi-conformance.yml:340`; `conformance/scripts/run-plan.sh`, `run-some.sh` | a shell unit test (`conformance/scripts/` tests) feeding `a[$(echo INJECTED >&2)]`; one `workflow_dispatch` with a bad input fails at validation (D-4) | S | Sonnet 5.5 |
| W4.6 | #630 | `gate.py` refuses a `--plan` absent from `baseline.json` unless `--new-plan` says it is new; at the next dispatch, `gate.py --record-unattended` runs over the artifact and the diff (expected empty) is committed. | `conformance/scripts/gate.py`; `conformance/baseline-unattended.json` | the `unittest` line of 1.0.1 W4.3; the dispatch (D-4) | S | Sonnet 5.5 |
| W4.7 | #627 | After a save that turned a switch on, when the refetched effective value is still `false`, the page says "saved — the organization has this surface off; it stays off until an organization administrator turns it on". | `frontend/src/pages/settings/SettingsPage.tsx:233` | a vitest case for the message; coverage stays ≥ the gate | S | Sonnet 5.5 |
| W4.8 | — | F4 review of the W4 diff. | | | — | Opus 5.5 |

Closes: #623, #624, #625, #626, #627, #628, #629, #630, #655.

---

## 6. Wave W5 — the FreeRADIUS recipe and guide (branch `claude/release-1.1.0-w5`)

All text, shell and compose; the one Rust file touched is `radius_e2e.rs`.
The e2e runs locally against FreeRADIUS 3.2.8 and `eapol_test` 2.10
(`docker/docker-compose.radius.yml`), as 1.0.1's W6 did.

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W5.1 | #643 | The fetch script ships as `docker/radius/fetch-crl.sh`: `out=$(openssl crl … -verify 2>&1)` and `[ "$out" = "verify OK" ] \|\| exit 1`; it refuses a list whose CRL number is lower than the installed one; it sends `If-None-Match` (#645). The guide embeds the file by reference, and `refresh_crl` in the e2e runs the script. | `docs/pki/freeradius.md:321-322`; `radius_e2e.rs:836-850` | the e2e: a list re-signed under a different key with the CA's name is refused and the installed list stays; a lower number is refused | M | Sonnet 5.5 |
| W5.2 | #644, #645, #646, #647 | Guide corrections in one commit: the reload re-reads `ca_file` and the lists, replace `ca.pem` atomically and never delete it without a restart, a logged store-replacement error means the old trust is in force (#644); fetch AXIAM directly or through a cache told `no-cache`, "+ any shared cache's `max-age`" in the bound, and the design note's §6.3 cell reads "fetch interval + `ca_path_reload_interval` (≥ 300 s) + `Session-Timeout`" with a dated correction (#645); `require_message_authenticator = yes` on the RadSec client and the NAS-firmware bullet (#646); the key re-encoding runs under `umask 077` through a pipe with no intermediate file, and drops out entirely where W1.10 has landed (#647). T-462's text follows #645. | `docs/pki/freeradius.md:111-113,223,344-358,376-377,402-408`; `claude_dev/radius-reply-profile-design.md` §6.3 | `scripts/check-doc-links.sh`; the e2e unchanged | S | Sonnet 5.5 |
| W5.3 | #648, #650 | The Architecture Invariants job gains a check that `docker/radius/` holds no Dockerfile and no `FROM`, and that the compose file's `image:` carries `@sha256:`; T-454 cites it and `cargo-deny`'s licence list (`deny.toml:121ff`) as its two tests. `radius-e2e.yml`'s path filter adds `crates/axiam-pki/src/crypto.rs`, `subject.rs`, `crates/axiam-api-rest/src/server.rs` and `docker/radius/**`. | `.github/workflows/ci.yml` (Architecture Invariants); `radius-e2e.yml:31-44` | the new script's self-test; the workflow runs on this PR (its filter now matches) | S | Sonnet 5.5 |
| W5.4 | #652 | The placement table writes `Tunnel-Private-Group-Id:0 = "20"` (and `:0` on `Tunnel-Type` and `Tunnel-Medium-Type`); the e2e asserts the tag octet in the Access-Accept. | `docs/pki/freeradius.md:278-280`; `docker/radius/raddb/`; `radius_e2e.rs` | the e2e's new assertion | S | Sonnet 5.5 |
| W5.5 | — | F4 review of the W5 diff. | | | — | Opus 5.5 |

Closes: #643, #644, #645, #646, #647, #648, #650, #652.

---

## 7. Wave W6 — RADIUS D4, the `rlm_rest` authorize endpoint (branch `claude/release-1.1.0-w6`)

**Binding documents:** `claude_dev/radius-reply-profile-design.md` (D5) in
full — §3 the profile model, §4 the segment pattern, §5 the write path and
its H1–H6 rule, §6.3 the decision, §7 isolation, §8 personal data — and the
spike's B-3 row (`claude_dev/radius-eap-tls-spike-2026-10-06.md:425`). The
note's §10 says D4 **must not** ship without §5.3 (the role-assignment and
certificate-binding gates): otherwise any `roles:assign` or `certificates:bind`
holder rewrites the placement model. W6.2 therefore precedes W6.4.

**The second wave that touches `schema.rs`:** **v100** (segments and
profiles), **v101** (the decision's audit index), **v102** reserved. Items
are sequential; W6.1 … W6.4 are one branch with one executor per item.

| Task | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|
| W6.1 | **Data model (v100).** `network_segment` (`/network/<site>/<segment>` as a reserved subtree of the resource tree, §4.1; `kind: access\|quarantine`, `vlan_id`, `filter_ids`, `version`) and `reply_profile` (§3.5: the `axiam-radius-reply/1` dictionary's attributes, typed; `session_timeout_secs` clamped at read to the tenant cap, §3.4). Repository traits in `axiam-core`, implementations in `axiam-db`, with the scope test and the newest-version bump. The six `network:*` permissions enter `permissions.rs` (§4.2). | `crates/axiam-core/src/models/`, `crates/axiam-db/src/repository/`, `schema.rs`; `crates/axiam-api-rest/src/permissions.rs:76ff` | repository tests: a segment outside `/network` is refused; a profile's `filter_id` outside its segment's envelope is refused (§5.2 H3) | M | Sonnet 5.5 |
| W6.2 | **The authorization function and the §5.3 gates.** One domain function in `axiam-authz` evaluates H1–H6 for a profile or segment write and the §5.3 table for a network-sensitive role assignment, unassignment, permission grant, role deletion and certificate **bind**, each at write time with `check_access` and deny-override in force. `roles.rs`, `permissions.rs` and `certificates.rs` `bind` call it. A test enumerates every write path that can create a profile, a segment, a network-sensitive grant or a binding and fails if one reaches the repository without the function (the T-429 lesson). `axiam-authz` is under `missing_docs`: documented from the first commit. | `crates/axiam-authz/src/` (new module); `handlers/roles.rs`, `handlers/permissions.rs`, `handlers/certificates.rs:527` | the enumeration test; assigning a `network:join` allow at `N` without `network:grant` at `N` is `403` with an audit row; binding a certificate to an account that already holds a join needs `network:grant` at every such node; a service account cannot bind to itself (H6) | L | Opus 5.5 |
| W6.3 | **Routes.** `/api/v1/network/segments` and `/…/profiles` (list, get, create, replace, delete), tenant from the token, each write conditional on the `version` read (`409`), each write route in its own bucket under `network_admin_per_min` wired as `scim_target_admin_per_min` is (`server.rs:1680ff`); the reactor's `network.pre_profile_write` / `network.pre_segment_write` veto hooks; an audit row for every write and every refusal with before/after values and the internal reason (§5.4). An envelope write that would strand a profile is `409` naming it. OpenAPI regenerated in-wave; `management-registry.json` regenerated (`scripts/gen-management-registry.py`) so W7's SDK ports reach the new operations. | `crates/axiam-api-rest/src/handlers/network.rs` (new), `server.rs`; the reactor hook of X1 | handler tests per route and refusal; limiter test per route; the registry's operation count rises by the ten operations and the drift job is green | M | Sonnet 5.5 |
| W6.4 | **The decision endpoint (T-468).** `POST /api/v1/network/decide`: the caller is a service account holding `network:decide` on the site it names, its token `cnf`-bound to its own certificate, metered on a machine preset keyed on the **authenticated caller**. The body carries the presented certificate (DER, base64) or its fingerprint and the site key; the endpoint resolves the certificate through `DeviceAuthService::authenticate_der`, refuses on tenant mismatch (§7), runs §4.3 (the account's `network:join` allows, deny-override, quarantine by deny, the most specific placement), and answers `{ allow: false }` with **no reason** or `{ allow: true, reply: … }` rendered from the typed profile with `Session-Timeout` clamped. Every decision writes one audit row under T-463's content rules and §8's personal-data rule. "No candidate" costs the same as a placement (T-457): one `check_access_batch`, the decision cache. A revoked certificate or a disabled account is `allow: false` at the next request (the CRL lag of T-462 closes for D4 deployments; the `Session-Timeout` bound remains). | `handlers/network.rs`; `crates/axiam-auth` (`DeviceAuthService`); `crates/axiam-authz` (`check_access_batch`, the decision cache) | `network_decide_test.rs`: allow with the profile's attributes; revoked → `allow: false`; another tenant's certificate → `allow: false`, same timing; quarantine deny beats a parent allow; a caller without `network:decide` on the site → `403`; a bearer (non-`cnf`) token → refused; timing: allow and no-candidate within the same budget | L | Opus 5.5 |
| W6.5 | **FreeRADIUS `rlm_rest` recipe and e2e.** `docs/pki/freeradius.md` gains the D4 section: the `rlm_rest` `post-auth` block posting the certificate and the site key with the service account's mTLS client certificate, the response mapping copying **only** the §3.2 attributes into the reply, and the revocation and quarantine latency of §6.3's D4 column. `docker/docker-compose.radius.yml` gains the profile (`rlm_rest` enabled against the AXIAM container). `radius_e2e.rs` gains the D4 cases: placement from a profile, revocation at the next authentication, quarantine, wrong site key. | `docs/pki/freeradius.md`; `docker/radius/raddb/`; `radius_e2e.rs`; `radius-e2e.yml` | the e2e, locally, exit 0; the workflow on the PR | M | Sonnet 5.5 |
| W6.6 | **Contract §36 and the threat model.** §36 "Network segments, reply profiles and the RADIUS decision (contract 1.62)": the ten management operations as SDK work (§27 surface, generated), the decision route as **not** SDK work (its caller is FreeRADIUS, mTLS-bound; an SDK carries nothing), the three-state answer, the no-reason refusal, the `cnf` requirement, the limiter. Threat entries: T-468 (the decision oracle) and the §5.10 entries that D4's elements build move from Not applicable to Mitigated with the W6.4 tests or to Open with their residual; T-462 gains the D4 column; T-457, T-463, T-464 gain the decision route; new entries from **T-478** for the segment/profile write surface (escalation through a profile, H1–H6) and the enumeration test. `Axiam.json` and the STRIDE table in the same commit; `website/src/security.ts` counts follow. | `sdks/CONTRACT.md` (new §36; record in §34.6 is W7.1's); `claude_dev/threat-model-stride.md` §5.10; `ThreatDragonModels/Axiam/Axiam.json` | `scripts/check-remediation-evidence.py`; the website's threat count generator | M | Opus 5.5 |
| W6.7 | F4 review of the W6 diff → `claude_dev/security-review-release-1.1.0-w6-<date>.md`. The review reads §5.2 H1–H6 and §5.3 against the code line by line. | | | — | Opus 5.5 |

Closes: #563 (D3, D4 and D5 shipped; option A stays on its reopen condition
in `claude_dev/radius-eap-tls-spike-2026-10-06.md` §1.4, recorded in the
closing comment).

---

## 8. Wave W7 — contract 1.62 and the eleven SDKs (branch `claude/release-1.1.0-w7`, cut from the plan branch after W1 … W6 are merged into it)

**The only wave that edits `sdks/CONTRACT.md`'s records.** W7.1 writes the
text; W7.2 … W7.12 are the eleven SDK pull requests, one session each, in
parallel, every one vendoring the plan branch's `CONTRACT.md`, `openapi.json`,
`management-registry.json` and `proto/` byte for byte, as 1.0.1's W5 did.
Each SDK PR is a draft until this PR merges (the drift check compares with
`main`).

**Version rule for the SDK PRs (Q5 and the 2026-10-14 decisions, §12).** The
1.61 tags are pushed before W7 (D-2). Every SDK gains a new helper form (Q2),
so every SDK's 1.62 release is a **minor** bump: Rust, Java, Kotlin and PHP
go `1.1.0 → 1.2.0`; the other seven `1.0.1 → 1.1.0`. The five SDKs whose
`user_id` loses its UUID type (Q7) record a source-breaking change in their
notes, as the Rust SDK did for 1.0.1; the SemVer promise in each README is
amended to say that a contract record may add a member or widen a type with a
minor bump, and that a removal waits for 2.0.0.

### 8.1 W7.1 — the contract text (Sonnet 5.5, S)

`sdks/CONTRACT.md` **§34.6 Contract 1.62**, one bullet per decision, each
naming the SDKs it binds:

| Item | Source | Text (normative unless marked) |
|---|---|---|
| a | #656 R101-04 | §33.3 rule 16: the CIBA list's `429` is spent per signed-in user **and** a per-address governor at ten times the allowance answers its own `429`; the OpenAPI response text (W3.8) says the same |
| b | #656 R101-05(b) | §27.15 note 10: the CA row goes to the organization's log because a tenant purge deletes audit rows at or before the export bound and the CA's revocation must outlive the tenant |
| c | #657 Q8 | §33.3 rule 13: the per-client `bc-authorize` bucket answers `{"error":"slow_down"}`, like the per-hint cap, and has since 1.0.0; the allowance bucket keeps `rate_limit_exceeded`. **Code unchanged.** |
| d | #657 Q1 | §34.5 cell for `CibaPendingList` reads "SDK work: no"; §33.3 rule 16 says an SDK carries nothing for it |
| e | #657 Q2, #631 | §32.2: every SDK offers a **change-taking** read-modify-write form for a stream (`(stream, changes) → body`) that sends `events_requested` and `expected_updated_at` as read and cuts `events_requested` to the new `events_allowed`; the plain converter remains and its doc names the caller's duty. API clients: absent `events_requested` resets, stated once more |
| f | #657 Q3 | §27.11 rule 5 and §32.2: an explicitly assigned `null` on `user_id` or `expected_updated_at` is "none" and the key is omitted; `null` is never sent |
| g | #657 Q4 | §32.2: `expected_updated_at` is the response's **own string**; a converter over a typed date model must keep the server's spelling next to the parsed value (C#'s form) |
| h | #657 Q6 | §32.2: the three meanings of `events_requested` are repeated at the `update_stream` call site in every SDK |
| i | #657 Q7 | §27.11 rule 5: the request `user_id` is passed as a string, untyped, so that a malformed value reaches the server and its `400` is surfaced; the **response** `user_id` stays typed where the language types it |
| j | #657 Q5 | the 2026-10-13 change-log line is amended: "wire-additive; source-breaking in Rust, Java, Kotlin and PHP, released as 1.1.0 there" |
| k | #657 Q9 | informative: T-450 and T-462 are Open for the FreeRADIUS recipe and the guide states the operator's residual |
| l | W6.6 | the §36 pointer and the ten new operations' §27 rows |

Then `sdks/openapi.json` is regenerated once more (description text), the
digest stamped (`scripts/check-spec-digest.py`), the registry regenerated.

### 8.2 W7.2 … W7.12 — the eleven SDK ports (Sonnet 5.5, one session each)

Every SDK: re-vendor; regenerate the §27 surface (the ten network operations
appear); the conformance fixtures for the new operations; the change-taking
SSF form (e); the `update_stream` call-site text (h); the CHANGELOG under the
minor-bump rule; the README's SemVer sentence. Per-SDK extras:

| SDK | PR size | Extras from §12 | Model |
|---|---|---|---|
| Rust | M | (i) `user_id: Option<String>` on the two request structs (source-breaking, recorded) | Sonnet 5.5 |
| TypeScript | M | (f) drop an assigned `null` on `user_id` ×2 and `expected_updated_at` (the `_NEVER_NULL_MEMBERS` rule Python has) | Sonnet 5.5 |
| Python | S | none beyond the common set | Sonnet 5.5 |
| Go | M | (i) `UserID *string` on the two requests | Sonnet 5.5 |
| Java | M | (g) `SsfStream` keeps `updatedAtRaw` next to `OffsetDateTime` and `ReplacementBodies.from` sends the raw string; (i) `userId` as `String` on the two requests (record constructors change, recorded) | Sonnet 5.5 |
| Kotlin | M | (g) as Java (`updatedAtRaw` next to `Instant`); (i) `userId: String?` on the requests | Sonnet 5.5 |
| PHP | S | the change-taking form already exists (`ReadModifyWrite::ssfStream`); the others | Sonnet 5.5 |
| C# | M | (i) `UserId` as `string?` on the two requests; (g) already C#'s form | Sonnet 5.5 |
| C | S | none beyond the common set (strings already) | Sonnet 5.5 |
| C++ | S | none beyond the common set | Sonnet 5.5 |
| Swift | S | none beyond the common set | Sonnet 5.5 |

### 8.3 W7.13 — conformance review (Opus 5.5)

`claude_dev/sdk-contract-1.62-conformance-review.md`, the 1.61 review's
method (§1 of that document) applied to the eleven heads: per-SDK report,
findings index, and a §5 of questions **only** for what §12 does not answer.
Medium-or-higher findings are fixed in the SDK PR before W8.

Closes: #631, #656.

---

## 9. Wave W8 — release readiness (on `claude/release-1.1.0`)

| Task | What lands | Model |
|---|---|---|
| W8.1 | **Regression gate** on the merged tree: `fmt`, workspace `clippy -D warnings`, the SAML-off check, every crate's tests one binary at a time where a crate is large (`axiam-db`, `axiam-api-rest`), the `client`-feature gRPC tests, every `scripts/check-*` and its self-test, the frontend lint, `tsc`, vitest with coverage, build; the website lint, `tsc`, build; the `radius-e2e` locally. Exit codes from the tool. Recorded in §13 as 1.0.1's §11.7 was. | Sonnet 5.5 |
| W8.2 | **Combined F4 review** of the whole diff against `main` → `claude_dev/security-review-release-1.1.0-<date>.md`; Medium and higher fixed here; Low and Informational filed on the next patch milestone. | Opus 5.5 |
| W8.3 | **Threat-model reconciliation**: every entry each wave edited, the five copies (`threat-model-stride.md`, `Axiam.json`, the STRIDE table, `website/src/security.ts`, `docs/compliance/FINDINGS.md`) agree once; model **2.42.0**; the counts in §7 of the model follow. | Opus 5.5 |
| W8.4 | **CHANGELOG `## [1.1.0]`**, one line per issue, upgrade notes that need an operator first (W3.2's 422; W1.10's key form; W3.5's knob; the `network:*` permissions and `network_admin_per_min`); `Cargo.toml` to `1.1.0` with the workspace crates that pin it; the pull request body on 1.0.1's shape (#657), with the `Closes` line for the 43 issues and the eleven SDK PRs listed. | Sonnet 5.5 |

---

## 10. The gate before every commit, and the rules that bind every wave

- `CLAUDE.md` in full: signed commits; narrowly scoped cargo commands;
  `cargo clean` between items; the swagger placeholder and `protoc` before any
  server build; `--no-default-features` where libxml2 is absent; exit codes
  from the tool, never a pipeline; no `[lints] workspace = true` on an
  undocumented crate; no new crate without a row in the layering table.
- Per commit, on the touched crates: `cargo fmt -p <crate> -- --check`,
  `cargo clippy -p <crate> --lib --tests -- -D warnings`, the touched test
  binaries (`--test <name>`), and for W2 the `build-no-saml` `cargo check`.
  Console tasks: `npm --prefix frontend run test -- <file>` and the
  type-check. `gate.py` tasks: its `unittest` line. Workflow tasks: one
  `workflow_dispatch` where the orchestrator has the means, else D-4.
- Phase 23 plan §7, unchanged: every new route carries a limiter from its
  first commit; every credential-bearing outbound request uses
  `guarded_fetch_no_redirect`; every refusal of a credential check costs one
  verify; every two-writer registry is written conditionally on the version
  read.
- **Schema**: W1 takes v99 (conditionally), W6 takes v100 … v102, in the
  order §2 and §7 fix; each is additive (`DEFINE FIELD IF NOT EXISTS`,
  `DEFINE INDEX IF NOT EXISTS`), with its scope test and the newest-version
  bump. No `UPDATE` backfill.
- **Contract**: no wave but W7 edits `sdks/CONTRACT.md`'s records; W6.6 adds
  §36 only. W1.10, W3.8 and W6.3 regenerate `sdks/openapi.json` in-wave so
  each wave's drift job is green, and W7.1 regenerates once more after the
  text. `management-registry.json` is regenerated by W6.3 and W7.1 only.
- **Threat model**: nothing enters without the test its mitigation names; a
  correction is recorded as a correction, dated, in the entry's own text.
  Each wave edits the entries its tasks name; W8.3 reconciles the five
  copies once.
- **Questions**: a contract question an executor cannot answer from §12 is
  recorded in §13 and in the conformance review's §5, never worked around
  and never answered by the executor.
- Where this plan and a file disagree, the file wins and the commit body says
  so. An executor that finds a task larger than sized stops at a clean commit
  and reports; the orchestrator re-sizes and re-models by §1.1.

---

## 11. Decisions requested from the maintainer

| # | Decision | Recommendation |
|---|---|---|
| D-1 | **The version.** 1.1.0 with D4 (W6), or 1.0.2 without it? W6 is the only wave that adds routes and the only one besides W1 that adds migrations, so dropping it changes nothing else. | **Answered 2026-10-14: 1.1.0.** if W6's first session re-sizes it past XL, ship 1.0.2 from W1 … W5 + W7 + W8 and keep W6 for 1.1.0. |
| D-2 | **Tag order.** Run PR #657's hand-off (steps 2 … 5: `v1.0.1` on the platform; `1.1.0` on Rust, Java, Kotlin, PHP; `1.0.1` on the other seven) **before** W7 starts, so the 1.62 SDK change logs follow a released version. | **Answered 2026-10-14: yes.** The `mass-tag.sh` dry run from #657's step 4, then two real runs: `--tag v1.0.1` for the platform and the seven, `--tag v1.1.0` for the four. The orchestrator checks `git ls-remote --tags` before W7 and asks if the tags are not there. |
| D-3 | **W2.3's key.** Principal `(tenant, sub)` alone, or the pair `(address, sub)`? | **Answered 2026-10-14: as recommended.** The executor's call on the tree's evidence (§3); the commit body records it. Ask only if it finds both wanting. |
| D-4 | **Runs the agent cannot start.** W4.5 and W4.6 need a `workflow_dispatch` of `fapi-conformance.yml`; W5.3 and W6.5 need `radius-e2e` to run on the PR. Who dispatches? | **Answered 2026-10-14: as recommended.** The orchestrator, through the GitHub Actions tool where the session has it; else the maintainer, once per item, on the orchestrator's request in §13. |
| D-5 | **W6.1's resource subtree.** `/network/<site>/<segment>` reserved in the existing resource tree (the note's §4.1), or a table of its own joined to resources? | **Answered 2026-10-14: as recommended.** The note's §4.1: a reserved subtree. Deny-override and inheritance come for free, and quarantine is a deny (§4.4). |
| D-6 | **The decision route's limiter preset.** Machine preset keyed on the authenticated caller (the note's §6.3), at what allowance? | **Answered 2026-10-14: as recommended.** `network_decide_per_min` in the machine presets at 6 000 (a hundred a second: a power-restore storm at one site), keyed on the caller's `sub`. |

---

## 12. Decisions already taken (PR #657's questions, answered 2026-10-14)

Recorded here so that no executor re-opens them. Each names the W7 item that
carries it.

| Q | Question (short) | Answer | Carried by |
|---|---|---|---|
| Q1 | `CibaPendingList` reachable by no generator | "Not modelled" **is** conformant; the §34.5 cell reads "SDK work: no" | W7.1 (d) |
| Q2 | Does the §32.2 cut bind a converter? | **All ten SDKs add a change-taking form** (PHP's `ReadModifyWrite::ssfStream` is the model); the plain converter stays with a documented duty | W7.1 (e), W7.2 … W7.12 |
| Q3 | An assigned `null` on a request member | **Dropped**: `null` is "none" and the key is omitted; TypeScript gains the rule | W7.1 (f), TypeScript port |
| Q4 | A converter over a typed `updated_at` | **Strict**: Java and Kotlin keep the server's own string, as C# does | W7.1 (g), Java and Kotlin ports |
| Q5 | SDK tags for 1.61 | **1.1.0 for Rust, Java, Kotlin, PHP; 1.0.1 for the other seven**; the change-log line amended | D-2, W7.1 (j) |
| Q6 | Three-meanings text at the `update_stream` call site | **Strict**: required in every SDK (Rust, TypeScript, Python, Go, C add it) | W7.1 (h), five ports |
| Q7 | A typed UUID on the request `user_id` | **Strict**: the request member is an untyped string in every SDK (Rust, Go, Java, Kotlin, C# change) | W7.1 (i), five ports |
| Q8 | §33.3 rule 13 `rate_limit_exceeded` vs the code's `slow_down` | **Fix the contract**; the code is unchanged | W7.1 (c) |
| Q9 | T-450 and T-462 Open for the recipe | **Keep Open** (eleven open High/Critical; the §6 register carries them) | W7.1 (k), W8.3 |
| Scope | Which issues | the 42 findings + contract 1.62 + **#563 D4**; #513 and #561 stay the maintainer's | §1 |

---

## 13. Wave results (written by the orchestrator as each wave lands)

### 13.0 Base commit

*(the `main` commit each W1 … W6 branch is cut from, and the date)*

**`3d011573e`** (`main` after the dependabot merge #662, which follows the plan
commits `e82e451` and `0233203`), 2026-10-14. All six wave branches
(`claude/release-1.1.0-w1` … `-w6`) and the plan branch `claude/release-1.1.0`
were pushed from it before the first executor started.

Orchestrator's environment, measured at the start: 4 cores, 15 GB RAM, about
30 GB of free disk, no `protoc`, no libxml2 headers, docker daemon stopped.
`protobuf-compiler`, `libxml2-dev` and `libxmlsec1-dev` were installed and
`dockerd` started. Because one Rust build fills most of the machine, the waves
run **one Rust executor at a time** (with `cargo clean` between items) rather
than six branches at once; non-Rust items (issue comments, console, text) may
overlap. SAGE is not connected in this session either.

**D-2 measured before any wave:** `git ls-remote --tags` shows **no `v1.0.1`**
on `ilpanich/axiam` (latest `v1.0.0-beta18`) and **no 1.61 tag** on any of the
eleven SDK repositories (latest `v1.0.0-beta17` each). W1 … W6 do not depend on
the tags; W7 does not start until they exist (D-2), and the maintainer was
asked for them at the start of W1.

**D-2 amended by the maintainer, 2026-10-14 (during W1).** 1.0.1 is **not
tagged**: the platform and the SDKs move straight to **1.1.0**. W7 therefore
does not wait for tags. Consequences, also decided by the maintainer:
- **Every SDK's contract-1.62 PR carries 1.1.0** (§8's version rule is
  superseded): Rust, Java, Kotlin and PHP fold 1.62 into their unreleased
  `[1.1.0]`; the other seven fold their unreleased `[1.0.1]` into `[1.1.0]`.
  The hand-off tags after merge are `v1.1.0` everywhere (§14 W8 superseded).
- **The never-tagged `[1.0.1]` sections are merged into `[1.1.0]`** and the
  `[1.0.1]` heading removed — in the platform `CHANGELOG.md` (W8.4) and in each
  SDK's change log (W7.2 … W7.12). The source-breaking notes of the four SDKs
  stay, under `[1.1.0]`.
- W7.1 (j)'s amended change-log line reads "released as 1.1.0" for all eleven.

### 13.1 W1 — what landed, and where the tree overruled the plan

**Head `dd3d3f10`** on `claude/release-1.1.0-w1` (from `3d011573e`), 2026-10-14:
eleven task commits, the F4 review and three in-wave fixes, all signed. One
executor per item at the row's model; the §10 gate before each commit (every
command exit 0 as reported by the tool); `cargo clean` between items (4.7 –
27.8 GiB each). From W1.5 on executors build with `CARGO_INCREMENTAL=0` and
line-tables-only debug info (local settings, no tracked file) because W1.4's
server tests filled 27.8 GiB. The clone was shallow, so
`check-remediation-evidence.py` failed on cited commits; the orchestrator ran
`git fetch --unshallow` before W1.3 and it passes since (37 verified).

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W1.1 #615 | `b97741b4` | Opus | `thisUpdate` clamped to `epoch.end − 1 s`, entries to `thisUpdate`; no high-water number (it would end #608's byte identity across replicas). The operator rule was derived, not assumed: an interval change stays monotonic at `nextUpdate` iff `I_new ≤ 2·I_old` (module doc, PKI guide, T-102). *Tree:* `list_identity` at `crl.rs:~767`, not `:709`. |
| W1.2 #616 | `da02b290` | Opus | Each CA's re-sign is one spawned flight behind a `watch` marker in `CaSlot`; joiners wait at most `permit_wait` and share its outcome (a `503` too); a hang-up no longer cancels the re-sign; `AxiamError: Clone`. *Tree:* the "shared flight precedent" was a mutex sharing a success only; the semaphore is at `boot.rs:705`. |
| W1.3 #617 | `e9a3ecca` | Sonnet | The sweep re-releases a revoked CA's own issuer when Vault refuses its forward as still an issuer (two triggers: the recorded error, or the refusal itself), then forwards; T-470 names the single-mount dependency and the not-adopted `issuer/<child>/revoke`. *Tree:* the sweep is `CertService::forward_pending_ca_revocations` in `axiam-pki/src/cert.rs`, not `cleanup.rs`; `revoke_within` unchanged. |
| W1.4 #618 | `4bd98bf4` | Sonnet | Step (b4) clears the account's certificate `metadata` (shared "belongs to the account" SQL with the revocation; `user_id` kept as the retry key); new job `certificate_retention` deletes rows eight days past `notAfter` in live tenants (bounded, stop-aware, two-replica safe); one `revocation_grace` definition feeds `KEPT_REVOCATION` and the new grace; T-187 and the GDPR doc: Art. 6(1)(f) / Art. 32, Art. 17(3)(b) withdrawn. *Tree:* (b4) at `cleanup.rs:~1975`; no migration. |
| W1.5 #619 | `29943ab7` | Sonnet | `sanitise_reason` at both audit appends and both forward logs; `b.` prefix masked; T-470 corrected. The returned reason stays whole (W1.3's matcher reads it). |
| W1.6 #620 | `843f2e81` | Sonnet | `axiam_auth::secrets::bootstrap_client()` on one no-redirect builder shared with the private-CA client; the redirect test builds through it (mutation-checked); T-476 corrected. *Tree:* the old builder had no timeout or TLS settings to carry. |
| W1.7 #621 | `4f3cf47b` | Sonnet | (a) "eight days after it expires" in the admin guide and `operate.ts`; (b) `vault_revocation`'s real failure rule; (c) `crates/axiam-server/tests/crl_purge_margin.rs` pins `REVOCATION_GRACE_SECS ≥ MAX_CRL_NEXT_UPDATE_SECS + 1 d` (fails at seven days); (d) `operate.ts` lists all 22 sweeps. *Tree:* `tenant_purge.rs` is in `axiam-db/src/repository/`; "Seventeen" was already stale (five jobs missing before W1.4). |
| W1.8 #622 | `a8324435` | Opus | (a) an orphan purge claims a tombstoned marker row under the orphan's id **and** re-checks for rows under the claim — each alone fails an interleaving; only the replica whose `DELETE … RETURN BEFORE` removes the marker records; (b) both issuance routes re-read the account after the create and revoke + `400` (nothing returned) when it is gone, and user deletion revokes once more after its tombstone; (c) `DELETE` of an unknown user revokes nothing; (d) the Vault failure record is conditional on the claim's lease (leaf and CA; core trait signature). T-472 corrected, T-336 amended. |
| W1.9 #653 | `09c76d56` | Sonnet | 20-octet CSPRNG serials (top bit clear) at every local signing site; Vault's `sign-verbatim` picks its own. **v99 taken**: no serial column existed, so v99 adds `serial` and UNIQUE `(issuer_ca_id, serial)` / `(parent_ca_id, serial)`; old rows `NONE` (no collision, safe upgrade), roots not recorded; scope test and newest version 99. *Tree:* no index existed (the plan allowed both); oracle in pki `crl_test.rs`. |
| W1.10 #651 | `c51a8677` | Sonnet | Ed25519 keys returned (and stored) as RFC 8410 v1; OpenSSL 3.0.13 `pkey` reads v1 (exit 0), refuses ring's v2 (exit 1); the FreeRADIUS re-encoding workaround is gone (W5.2 reads this); spec regenerated (descriptions incl. the CRL `503` sentence of W1.2), registry digest refreshed. *Tree:* `to_pkcs8_pem` is the RSA hand-off; the fix is at the four `serialize_pem` sites. |
| W1.11 #649 | `28dc3eb6` | Sonnet | The common name refuses control, non-space whitespace, bidi/zero-width/format characters, stray spaces and > 64 characters (characters, not bytes), never echoing the value; T-461 amended. *Tree:* the CSR path (`inspect_csr`) was unchecked and the Vault intermediate default could exceed 64 — both now refused. |
| W1.12 | `76821676` | Opus | `claude_dev/security-review-release-1.1.0-w1-2026-10-14.md`: R110W1-01 **Medium**, R110W1-02 Low, R110W1-03 … -06 Informational. |
| fix | `b24e34a1` | Sonnet | **R110W1-01** (Medium): the retention batch reads the live tenants once (`LET $live`); 2 000 + 201-tenant test (old statement 29 s). |
| fix | `154e0d5e` | Sonnet | **R110W1-02** (Low, fixed in-wave because the wave closes #649): a CSR with two CNs is refused and every subject attribute passes the value rules, local and Vault paths, before any Vault request; T-461 corrected. Value rules rather than refusing O/OU/C: local paths drop them today and client tooling sends them. Spec regenerated (one description). |
| fix | `dd3d3f10` | Sonnet | **R110W1-03**: registry `spec_digest` refreshed (`gen-management-registry.py --check` exit 0; 190 operations, 28 namespaces). |

Filed on the next patch milestone (named in each body: `1.1.x` does not exist
yet and the session cannot create milestones): ilpanich/axiam#664 (R110W1-04),
#665 (R110W1-05), #666 (R110W1-06 (a)–(c); its (d) is W8.4's), and three
executor follow-ups the review confirmed: #667 (Vault clients without a
request timeout), #668 (an issuance between the Art. 17 purge's (b4) and its
anonymization survives), #669 (a unique-serial violation answers `500`). The
review rejected four others (request-path issuer-release retry; the 256-character
cut of the stored reason; T-102 citing Art. 17(3)(b); an epoch-premise test —
`epochs_are_half_the_interval_and_aligned_for_every_replica` exists).

For later waves: **W7.1** — `CONTRACT.md` §35 still names "a datastore clock
ahead" among the ways the CRL number falls; after W1.1 only the interval change
and replica-clock straddle remain, and §35 should carry the `I_new ≤ 2·I_old`
rule (an informative-section text change, not a §12 question). **W8.3** —
`website/src/threatModel.ts` and `threat-modeling-and-security.md` copies of
T-102, T-187, T-470, T-476 lag. **W8.4** — upgrade notes: the first
`certificate_retention` runs delete every row eight days past `notAfter` (up to
10 000 per tick); keys issued before 1.1.0 stay in the long PKCS#8 form;
subjects with control characters, two spaces or > 64 characters are now `400`;
v99 and random serials. `check-sdk-artifact-drift.py` exits 1 until the SDKs
re-vendor (W7), as expected.

### 13.2 W2

**Head `3652db6d6`** on `claude/release-1.1.0-w2` (from `3d011573e`), 2026-10-15:
four task commits, one fix of W2.1, the F4 review and one in-wave fix, all
signed; the SAML-off `cargo check` before every commit. **Gap found and closed
in this wave:** the executors' gate ran without CI's `RUSTFLAGS=-Dwarnings`
(`ci.yml:14`), so W2.1 left an unused binding that only warns locally and
fails CI's "Build (SAML off)" job; from W2.4 on every executor builds with
`RUSTFLAGS=-Dwarnings`. W1 was gated without it; W8.1 runs with it (and the
plan-branch merge checks it first).

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W2.1 #654 | `cad058673` | Sonnet | `CryptoGate` (`axiam-federation/src/saml_gate.rs`) bounds every SAML acquire by `hash_acquire_timeout_secs`; `with_crypto_semaphore` replaced by `with_crypto_gate` so no composition can pass an unbounded semaphore. Busy ACS → the same `401` and body as a bad signature; metadata → its failure; IdP SSO/SLO receiver → `503` + `Retry-After: 5`, no state written. The IdP's own signing (authenticated) left unbounded. *Tree:* T-477, not named by the plan, was the entry stating the unbounded wait (amended with T-102, T-474). |
| W2.2 #632 | `b1ddc8947` | Sonnet | `federation_link_oidc_callback`, `federation_link_saml_acs`; `rate_limit_bucket_names_test.rs` (source scan of `crates/*/src`, allow-list with exact counts). *Tree:* `login` is registered once (its second spelling is a doc example), so two intentional shared names (`directory_config` ×3, `uma_rreg` ×2), not the three the 1.0.1 combined review §6 names. |
| W2.3 #633 | `ff8ca52a0` | Opus | **D-3: the principal `(tenant, sub)` alone** — `(address, sub)` leaves one token from many addresses unbounded. A `cnf` token is keyed `(address, tenant, sub)` (its proof is checked after the limiter). The key comes from the audit middleware's cached verified identity, so no extra verification; no identity → address. `RateLimitKeyMode::Principal` cannot be set from `AXIAM__RATE_LIMIT__KEY`. *Tree:* `authz.rs:215-245` checks only that a credential is present, so the limiter runs before verification and the reused verification is the audit middleware's (`axiam-audit/src/middleware.rs:612-664`, wired `boot.rs:3069`). |
| fix | `fea3b64d6` | Sonnet | W2.1's `hash_acquire_timeout_secs` binding gated `#[cfg(feature = "saml")]`; SAML-off `check` and `--tests` exit 0 under `-Dwarnings`. |
| W2.4 #634 | `c7ec9a1c2` | Sonnet | Both `saml_idp/sign.rs` self-checks parse with `receiver_parser_options()`; a source-scan test pins both calls (a refused self-check reads the same either way, so the call is what is pinned). |
| W2.5 | `3d2489dc8` | Opus | `claude_dev/security-review-release-1.1.0-w2-2026-10-15.md`: nothing Medium or higher; R110W2-01, -02 Low; -03 … -06 Informational. |
| fix | `3652db6d6` | Sonnet | **R110W2-01** (Low, fixed in-wave because the wave closes #633 on it): the five authenticated federation flow routes keep an outermost per-address backstop at `end_session_per_min × 10` (`FEDERATION_FLOW_BACKSTOP_FACTOR`, the CIBA list's pattern, in-process per replica); four tests, mutation-checked; T-474 and the two deployment rows. |

Filed on the next patch milestone (`1.1.x`, named in each body):
ilpanich/axiam#670 (R110W2-02, Low — `DPoP`-scheme requests not attributed by
the audit middleware), #671 (R110W2-03 — ten authenticated waiters on the
crypto semaphore still unbounded; the Redirect-binding query check stays
ungated by decision), #672 (R110W2-04 — the bucket-name scan's blind spots),
#673 (R110W2-05 — in-process governors never swept), #674 (R110W2-06 — text
and the unpinned audit-before-limiter order; its (h), the website copy, is
W8.3's). For **W8.4**: the CHANGELOG's #614 entry (`~301-302`) names the old
buckets; for **W6**: its new `network_*` buckets must pass
`rate_limit_bucket_names_test.rs` after the merge.

### 13.3 W3

**Head `b40b33a67`** on `claude/release-1.1.0-w3` (from `3d011573e`), 2026-10-15:
eight task commits, the F4 review and one in-wave fix, all signed; every gate
command exit 0 under `RUSTFLAGS=-Dwarnings`. `sdks/openapi.json` was held until
W3.8 and regenerated once (the review's own rebuild is byte-identical).
**Re-model:** W3.5 ran at Opus, not Sonnet (§1.1): "refused calls no longer
counted" made the admission a check-then-increment under concurrency.

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W3.1 #635 | `3fcac1532` | Opus | `token_device.rs`: the device grant authenticates its client at both endpoints through the other grants' path (registered method, live tenant, FAPI `enforce_client_authentication` / `enforce_token_request`, grant check, `cnf` at the poll); an unknown client costs one HMAC verify against a fixed hash no secret produces; a foreign `client_id` is `invalid_grant` before `record_poll`; no refusal spends or reveals a grant; device tokens are bound (`cnf`, `token_type: DPoP`) for DPoP/mTLS clients. *Tree:* W3.7(a) folded in; W3.7(b) answers **`invalid_client`** (client authentication reads the tenant), not the plan's `invalid_grant`; `boot.rs` / `state/mod.rs` changed (service generics). |
| W3.2 #636 | `1d9b8664b` | Sonnet | Admin `PUT` of a `dcr`/`cimd` row refuses (422 `scope_exceeds_ceiling`, naming the scopes) a scope outside the effective `dcr_allowed_scopes`; a row beyond a since-narrowed ceiling may keep what it holds but gain nothing. *Tree:* `AxiamError::Validation` is 400 and there is no `Unprocessable`, so a REST-crate `unprocessable_entity` helper; `POST` can only create `admin` rows and there is no `PATCH`, so only update refuses. |
| W3.3 #637 | `fe6878687` | Opus | `RESERVED_ACTION_NAMESPACES` (`tenants.`, `gdpr.`, ASCII-case-insensitive) refused from AMQP (to the DLQ, after the signature checks, before the nonce); the purge bound is `min(exported_through, receipt timestamp)` of the receipt found in the deleted tenant's own log (none → keep the whole trail); deletion refuses (409) a receipt claiming rows after itself. *Tree:* the namespaces live in `axiam-core` (amqp may not depend on db). |
| W3.4 #638 | `f07713169` | Sonnet | The hint cap reads the previous window with `peek_count` (was an upsert); new job `rate_limit_bucket` deletes rows older than 2 × the longest window in use (600 s, derived from the three writers) **+ 60 s clock margin**, bounded, two-replica safe. *Tree:* the margin is the executor's addition (lenient-only); no `updated_at` index (no migration owned). |
| W3.5 #639 | `8492128e7` | **Opus** (re-modelled) | `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_HINT` (default 3, `≥ 1`, checked at boot because the CIBA service is built before `validate()`); refused calls are taken back by a conditional decrement; an "overtaken" rule closes a 1.0.1 late-call hole; the bound — at most the allowance in any two consecutive windows, across replicas — holds exactly, errors strict-side only. Conformance harness sets 1000. |
| W3.6 #640 | `3ae58f5d4` | Sonnet | `AuditLogRepository::datastore_now()` (required, no `Utc::now()` default) bounds the export; the receipt is written after the last page. *Tree:* no server-time helper existed (eleven doubles in six crates gained it); `audit.rs:355` unchanged. |
| W3.7 #641 | `afa4dce4f` | Sonnet | The tombstone transaction deletes `device_grant`; the `sa_` `client_credentials` path answers a tombstoned tenant `invalid_client` after its verify (it answered a distinguishable `invalid_request`). (a)/(b) were W3.1's. |
| W3.8 #642 | `ee2a3bacc` | Sonnet | (a) R101W3-01 named as the reason (module doc, the `[1.0.1]` #610(d) entry corrected in place, T-289); (b) the client `DELETE` text; (c) CIBA mints no ID token without `openid`; (d) `boot.rs` re-indented; (f), (g) left, reasons in the commit; spec regenerated (W3.1's fields and 401, W3.2's 422, (b), #656's per-address backstop text, the tenant `DELETE`'s 409); registry digest-only (190 / 28). **(e) not obtained:** 1.0.1's W3.2 quick bench (`just bench-quick` Cell 1, `claude_dev/quick-bench-runbook-2026-08-16.md`) needs `just`, k6 (`dl.k6.io` denied by the proxy) and an AXIAM server image (`ghcr.io/ilpanich/axiam/server:1.0.1` not found; a local fat-LTO release build exceeds this machine's disk), and is a before/after pair (`7be5e8094~1` vs HEAD). Left for the maintainer's bench box. **Obtained 2026-10-15 on the maintainer's box** (i7-8750H, 6 c / 12 t, 30 GiB, governor `powersave`; three local `build=1` images; report kept as [`quick-bench-w32-2026-10-15.md`](quick-bench-w32-2026-10-15.md)): `bench-quick` Cell 1, A = `7f5330cf4` vs B = `7be5e8094` — unbound 2149.2 → 2188.8 req/s (+1.8 %), p50 4.50 → 4.28 ms (−4.9 %); certificate-bound 1993.8 → 2183.6 req/s (+9.5 %), p50 5.06 → 4.32 ms (−14.7 %); p95/p99 +2.5 … +10 % (a separate ~45–53 ms stall mode, not a per-request cost); 0 errors (B: 262 356 calls). In-run noise floor 7–15 % (A's two sub-arms on one binary); **verdict: within noise, no regression above ~10 % single-window variance.** Informative arm C (W3 head `b40b33a67`) within ~1 % of B. Single unrepeated 45 s windows — indicative, not a matrix result. The run found a recipe bug: `bench-quick` on p3-mtls fails at k6 init unless `BENCH_CERTS_DIR` is absolute (filed). |
| W3.9 | `f70976a26` | Opus | `claude_dev/security-review-release-1.1.0-w3-2026-10-15.md`: R110W3-01 **Medium**, -02 Low, -03 … -12 Informational. |
| fix | `b40b33a67` | Opus | **R110W3-01** (Medium): the public-client token bucket keyed on the transport peer, so behind the proxy one address could hold every public client's device polls at `429 slow_down`; it now keys on the route limiter's client address (`select_rate_limit_ip`, one reader of `TRUSTED_HOPS`), audit rows keep the peer; also fixes public code and refresh requests (exposed since T21.2, which had no flood test — one added). |

Filed on `1.1.x` (named in each body): ilpanich/axiam#675 (R110W3-02, Low —
existing confidential device clients are refused after the upgrade), #676 …
#684 (R110W3-03 … -10, -12), #685 (the public-client bucket now never refuses
first), #686 (Low, pre-existing T-212: without a proxy the limiters key on a
caller-written `X-Forwarded-For`). R110W3-11 (contract text the wave made
stale) is W7.1's, below.

**Contract question for the maintainer (§10: recorded, not answered; also for
the conformance review's §5).** `sdks/CONTRACT.md` §14.1 (`:2859-2861`):
"`device_authorize` is **unauthenticated** … SDKs MUST NOT send
`client_secret` on it". Since W3.1 a confidential device client must
authenticate at both device endpoints (public clients send nothing and are
refused if they do), so an SDK following §14.1 cannot run the device grant for
a confidential client. Options from the review: (a) §14.1 keeps
"unauthenticated" for public clients and SDKs send a confidential client's
credential at both endpoints; (b) the server returns to §14.1 at the start
endpoint (reverses part of W3.1; not recommended); (c) device clients must be
public at registration. **Asked of the maintainer on 2026-10-15; W7 does not
start without the answer.**

**Answered by the maintainer, 2026-10-15: option (a).** §14.1 keeps
"unauthenticated" for a public client; an SDK client configured with a
credential (client secret — post or Basic —, `private_key_jwt`, or an mTLS
certificate) sends it at **both** `device_authorize` and the poll, by the same
rules as its other token requests. W7.1 rewrites §14.1/§14.2 (with the stale
§14 text listed below) and every SDK port implements it. The server is
unchanged. **R110W3-02 (#675), also answered:** beyond W8.4's upgrade note,
1.1.0 adds a **boot-time warning** counting the confidential clients that hold
the device grant (a small server change on the W3 branch, after W6.3; reviewed
by W8.2); "an admin `PUT` may turn a device-only client public" stays on #675. The warning landed as `6e7a0015d` on the W3 branch (Sonnet, 2026-10-15): `OAuth2ClientRepository::count_confidential_with_grant` returns the number of clients and tenants, both grant spellings counted, and one `warn!` at boot names the counts only — W3 head is therefore `6e7a0015d`.

For **W7.1** (R110W3-11, stale contract text): §14 intro (`:2842-2846`, device
tokens' `client_id` claim and `403`); §14.2 (the poll's `401 invalid_client`;
DPoP proof per poll and `token_type: DPoP`); §27 rule 2 (`:9068`, a deleted
client's poll is `invalid_client`); §33.3 rule 13 (the hint-cap setting,
refused calls not counted, SDK suites raise it); §8/§8b (the reserved
`tenants.` / `gdpr.` actions); the admin `PUT`'s 422 `scope_exceeds_ceiling`;
`tenants.delete`'s second 409. For **W8.4**: upgrade notes for W3.1 (confidential
device clients must send their credential at both endpoints, the poll requires
`client_id`; review §2.2 text), W3.2's 422, W3.5's setting.

### 13.4 W4

**W4.1 (#626, #629) — done 2026-10-14, no code.** Comments:
ilpanich/axiam#626 (issuecomment-6171974235) and ilpanich/axiam#629
(issuecomment-6171975861), verified on `main` @ `3d011573e`. Tree vs plan:
#626's two entries start one line earlier than §0.1 says (`CHANGELOG.md:586`
and `:602`, added by `52d4219`); #629's text was taken by `fe7b9d2` (1.0.1's
threat-model reconciliation commit, not a separate W7.3 commit), the prod
compose file and the k8s manifest name only `ORDERLY_STOP`, and `operate.ts:122`
names neither constant but links the guide's "Stopping, and the grace period" —
the five steps, 37 s and the 3 s lease-loss drain are in all four.

**Head `6faa925cd`** on `claude/release-1.1.0-w4` (from `3d011573e`), 2026-10-15:
six task commits and the F4 review, all signed; every Rust gate under
`RUSTFLAGS=-Dwarnings`. No in-wave fix (nothing Medium or higher).

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W4.2 #655, #624 | `fff66606b` | Opus | `cleanup::AuditedWork`: a tenant purge (claim → `tenants.purged`), an orphan purge and a user's whole purge (→ `account_deletion` completion and `gdpr.user_pseudonymized`) each run as a spawned unit; `join_cleanup` waits for the cleanup task and then the running unit against one deadline (`budget.cleanup`) and aborts at it. The stop is checked between tenants; a unit gives up before its point of no return (the anonymization; the tenant row's removal) and never crosses it once stopping. `PurgeClaim` drop guard releases the claim on every exit but success. `purge_tombstoned` split in two (`axiam-db`). *Tree:* the guide, T-444 and `join_cleanup`'s doc already listed the tenant purge (1.0.1 W7.3), so the lists were restated; the unit is waited for inside the cleanup bound, not the slack (kept for W4.4); the erasure unit is the whole user purge (the SSF `with_cause` task-local does not cross a spawn). |
| W4.3 #625 | `dad34dbe9` | Sonnet | `axiam.audit.dlq` is emitted before the file append; the file's failure has its own event. Not spawned (a detached write would escape the bounded stop join); residual recorded in T-108. |
| W4.4 #628 | `e0670df5e` | Opus | The cleanup task is told to stop when the REST listener returns (SIGTERM) and at the loss itself (lease-loss stop callback), closing W4.2's 0–7 s gap; the lease release is a budget step (`ShutdownBudget::lease_release`: 1 s orderly, 0 on loss) via `release_lease_within`; a loss seen during a SIGTERM stop now skips the release and exits non-zero (the guide said so; the code returned Ok). **The arithmetic changed:** `ORDERLY_STOP` = 20 + 5 + **1** + 2 + 5 + 5 = **38 s**, `FATAL_STOP_BACKSTOP` **39 s**, grace 40 s, `LEASE_LOSS_STOP` 13 s — guide, both compose files, k8s and `operate.ts` updated. *Tree:* the 1 s could not fit the 1 s backstop margin (37 + 1 = 38), so it became a step; the existing cut test is a lib test (`profile.rs:518`); there is no sleeping route, so the new case holds a sign-in's body. |
| W4.5 #623 | `1ab46dd50` | Sonnet | `fapi-conformance.yml` validates `plan_name` / `module_timeout` in a first step before checkout (inputs via `env:`, `%q` errors, validated values via `$GITHUB_ENV`); `conf_require_uint` in `lib-env.sh` refuses non-numeric values before any arithmetic in `run-plan.sh` / `run-some.sh` (and `CONFORMANCE_SUITE_WAIT`); `conformance/scripts/tests/validate_inputs_test.sh` (281 checks), wired into CI next to the gate's unittest. |
| W4.6 #630 | `3b0a540a7` | Sonnet | `gate.py` refuses a plan `baseline.json` does not name unless `--new-plan` (repeatable; refused for a baselined plan or one not also `--plan`); 37 unit tests. *Tree:* the gate's rules live in `claude_dev/fapi-conformance-runbook.md` ("The CI gate"); `docs/conformance/README.md` points to it. **Second half not done:** re-recording `baseline-unattended.json` needs a full `fapi-conformance` dispatch, i.e. running the conformance suites, which the orchestrator does not do — **for the maintainer (D-4):** dispatch on `claude/release-1.1.0-w4` with `axiam_image` empty, `plan_name` default, `module_timeout=30`; then `python3 -I conformance/scripts/gate.py --results <artifact>/conformance/.run/results --record-unattended` and compare `.plans` only with `baseline-unattended.json` (expected empty; then only `source` gains a provenance note naming the run, keeping `38317560409`). **Done 2026-10-15** (`6faa925cd`): at the maintainer's go-ahead the orchestrator dispatched run 38779757053 (on `1d6498165`, `module_timeout=30`, AXIAM from source; every step success; gate green, 95 tolerated = 94 WAITING + 1 SKIPPED); the blob store refused the artifact (403), the maintainer uploaded it (zip sha256 `43057373…5808c60`); `--record-unattended` over it exit 0 and its `plans` are identical to the baseline (diff exit 0, 27 / 27 / 40), so the lists are now a recording; only `source` gained the dated provenance. |
| W4.7 #627 | `5445dadc0` | Sonnet | After a save that turned a surface on, the settings page says it stays off while the organization keeps it off (only then; not on a failed read-back). *Tree:* no i18n or toast exists — the page's own alert block; the save handler is at `~:386`. Coverage 96.55 % ≥ 96.1. |
| W4.8 | `1d6498165` | Opus | `claude_dev/security-review-release-1.1.0-w4-2026-10-15.md`: R110W4-01 … -07, all Informational. |

**D-4 dispatch by the orchestrator** — the bad-input run of W4.5, run
38737745432 on `3b0a540a7` with `module_timeout = a[$(echo INJECTED >&2)]`:
"Validate dispatch inputs" failed (exit 1) before checkout; the log carries the
value only `%q`-escaped, never a bare `INJECTED`. The `always()` steps then ran
on the empty workspace (noise; R110W4-05).

Filed on `1.1.x`: ilpanich/axiam#687 (R110W4-01), #688 (-02), #689 (-03), #690
(-04), #691 (-05), #692 (-07); R110W4-06 (T-472 still says #655 is not fixed) is
**W8.3's**. The review rejected one follow-up: a lease release that commits
after its 1 s bound cannot remove a successor's lease (`DELETE … WHERE holder =
$holder`, a per-process UUID). For **W8.4**: the stop is 38 s (was 37) and the
backstop 39 s (was 38); the grace is unchanged.

### 13.5 W5

**Head `285b48b1a`** on `claude/release-1.1.0-w5` (from `3d011573e`), 2026-10-15:
four task commits, the F4 review and four in-wave fixes, all signed. **The
RADIUS e2e runs on this machine:** `eapol_test` 2.10 from apt
(`eapoltest`), the pinned FreeRADIUS 3.2.8 image pulled (one Docker Hub 429,
then fine). Baseline before any change: `AXIAM_E2E_RADIUS=1 cargo test -p
axiam-server --no-default-features --test radius_e2e` exit 0 (328 s, 285 s
revocation lag); exit 0 again after W5.1 and W5.4. **D-4, by the orchestrator:**
`radius-e2e.yml` dispatched on the branch — run 38761953931 on `63fc3d7d2`
(the workflow's first-ever run) **success**; run 38768034553 on `285b48b1a`
(compiles and runs the fixes' uncompiled e2e edit and the new script harness)
**success**.

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W5.1 #643 | `384d2c772` | Sonnet | `docker/radius/fetch-crl.sh`: installs only a 200 that parses, whose `openssl crl -verify` output is exactly `verify OK` (openssl exits 0 on "verify failure"), whose CRL number is not lower than the installed one; sends the stored ETag, treats 304 as unchanged; `mktemp` + `mv`. The guide links it (no second copy); the e2e runs it on the host against a loopback mirror (forged, lower-numbered, 304 cases; each check's removal turns the e2e red). T-462 amended (Open). *Tree:* the snippet sat at `freeradius.md:389-418`, `refresh_crl` at `~:933`; T-450 (MD5 obfuscation) untouched. |
| W5.2 #644–#647 | `8a91f9c38` | Sonnet | Guide: what the reload re-reads, `ca.pem` replaced atomically and never deleted without a restart, "Error replacing X509 store" means the old trust holds (#644); fetch direct or `no-cache`, the bound "+ any shared cache's `max-age`", the note's §6.3 cell with a dated correction (#645); `require_message_authenticator = yes` on the RadSec client and the NAS's half of Blast-RADIUS (#646); the re-encoding under `umask 077` through a pipe, octal `printf` (the `\x30` form only worked under bash) (#647 — W1.10 removes the workaround; the merge takes W1). *Tree:* the shipped `clients.conf` already had the option. |
| W5.3 #648, #650 | `d215a644b` | Sonnet | `scripts/check-radius-vendors-nothing.py` (`--self-test`, 18 cases) in Architecture Invariants; T-454 cites it and `cargo-deny`'s licence list; `radius-e2e.yml`'s filter gains `crypto.rs`, `subject.rs`, `server.rs` and the script. *Tree:* the licence list is `deny.toml:~118-136`, run by the `security-scan` job. |
| W5.4 #652 | `63fc3d7d2` | Sonnet | `:0` tags on the three VLAN attributes in the guide and the e2e's generated table; the e2e pins the Accept's octets. ***Tree overruled the plan:*** FreeRADIUS 3.2.8 encodes `Tunnel-Private-Group-Id:0 = "20"` exactly as untagged (`3230`; RFC 2868 §3.6 allows it); only a non-zero tag adds an octet; the integers always carry `0x00`. So "fail on the untagged form" is impossible; the assertion fails on any non-zero tag (`:1` → red). `docker/radius/raddb/` holds no placement entries (generated per run). The design note's "tag `0x00`" (`radius-reply-profile-design.md:83,178,722`) is wrong for FreeRADIUS — **W6's to correct**, since D4 renders the reply. |
| W5.5 | `90924ed4c` | Opus | `claude_dev/security-review-release-1.1.0-w5-2026-10-15.md` (no cargo; the e2e evidence above): nothing Medium or higher; R110W5-01 … -04 Low, -05 … -10 Informational; a trial merge with W1. |
| fix | `507899207` | Sonnet | **R110W5-01**: one well-formed entity-tag only (never `*`), bound to the installed file's SHA-256; a 304 counts only with the tag sent, else one unconditional fetch. |
| fix | `f0fe8b064` | Sonnet | **R110W5-02**: a lock for the whole run (`flock`, present in the pinned image; `mkdir` fallback with stale-lock breaking); a run that finds it held exits 0 untouched. |
| fix | `b84d0bcb2` | Sonnet | **R110W5-03**: `curl -q`, scheme pinned, `--max-redirs 0`, `--globoff`, `--url`; `http://` only with `FETCH_CRL_ALLOW_HTTP=1`; the e2e gains the refused-HTTP case. `docker/radius/tests/fetch-crl-test.sh` + `crl-stub.py` (64 checks, dash and bash, each fix's checks red on the previous script) run in `radius-e2e.yml`. |
| fix | `285b48b1a` | Sonnet | **R110W5-04**: T-454's correction states exactly what the check does and does not catch (status Mitigated on the narrower claim). |

The four Low findings were fixed in-wave because they are in the script and the
check this wave ships for #643 and #648. Filed on `1.1.x`: ilpanich/axiam#693
(R110W5-05 — the guide's RadSec block fails `-XC` and its
`require_message_authenticator` is inert on a RadSec client), #694 … #698
(R110W5-06 … -10). **For the merge:** the only conflict is the Ed25519 bullet of
`freeradius.md` — take W1 (W1.10's removal settles #647); after the merge the
guide's §4 must say a "lower than the installed" refusal is expected once after
an interval change (W1.1) and link the PKI README's rule. **For W8.3:** the
STRIDE text and `freeradius.md:618` still say all four Mitigated RADIUS entries
are tested by the e2e (true of T-449, T-456, T-459 only).

### 13.6 W6

**Maintainer decision, 2026-10-15 (asked by the orchestrator after W6.3):** the
per-tenant cap `network.session_timeout_max_secs` (stored by W6.1, enforced by
the gate's H3 and at read; the note names no writer) **is exposed under
`network:admin`**: `GET`/`PUT /api/v1/network/policy`, writable by
`network:admin` at the `/network` root (lowering always allowed, raising
audited), conditional on the row's version. Two more management operations
(the registry reaches **202 / 29**), an executor after W6.4 on this branch,
and §36 text in W6.6.

**Corrected by the maintainer, 2026-10-15 (after W6.3b, `f479c6530`):** the
first question named `network:admin`, which the note defines as administrative
login to a segment's NAS devices and which is **not grantable** under option B,
so the route as built was writable by nobody. The cap write is guarded by
**`network:segments_write` at the `/network` root** instead: the cap is the
`Session-Timeout` envelope every profile is clamped to, and envelopes are
`segments_write`'s (H3 keeps envelope writers apart from profile writers).

**Maintainer decision, 2026-10-15: the admin console is in 1.1.0.** The plan had
no console work for D4 (nor did the design note), and `frontend/src` has no
network page. A new item **W6.8** (Sonnet, M–L) lands on this branch after
W6.6 and before the F4 review (W6.7), so the review reads it: a "Network
access" section — the segment tree (`/network/{zones|quarantine}/<site>/<segment>`),
the reply-profile editor (the typed dictionary; `Session-Timeout` shown
clamped), the tenant cap (`GET`/`PUT /network/policy`), gate refusals (403 with
the rule) and 409s surfaced — plus two console touches for W3's API changes:
the OAuth2 client form shows the 422 `scope_exceeds_ceiling` message, and a
confidential client holding the device grant is told it must authenticate at
both device endpoints. Gate: vitest with the coverage threshold, `tsc`, lint.

**W6.6's four contract questions (recorded per §10), answered by the
maintainer on 2026-10-16:** (1) the network `PUT`s keep **`replace_*`**
(full-body, version-conditional replacements, as §27.4 rule 5's existing four;
the count becomes seven); (2) the generic OpenAPI components are **renamed**
before W7 (`ReplyProfile` → `NetworkReplyProfile`, `ServiceType` →
`RadiusServiceType`, `TerminationAction` → `RadiusTerminationAction`, and any
other generic network schema name), spec and registry regenerated on this
branch; (3) `administrative_user` and `nas_prompt_user` **leave the spec**
(option B refuses them; option A may add them back additively; the server's
refusal stays); (4) **`network` is a §27.6 manifest namespace in 1.62**
(natural keys: a segment by site + kind + name, a profile by its segment, the
policy as a singleton) — §27.6 text by W7.1, `plan`/`apply` in every SDK port
that ships §27.6.

**W6.7's review (`dacca3318`) and the maintainer's answers, 2026-10-16.**
R110W6-01 (Medium: H6 was not applied to the §5.3 writes that change the
writer's own placement — a service account could assign itself join and
release its own quarantine) is fixed in-wave (`21ab64fbc`, T-482 → Mitigated,
totals 487 / 454 / 23 / 10); R110W6-13 (the frontend coverage matrix lacked the
network handlers, `docs-ci` red) is fixed (`22fcc5098`). Asked of the
maintainer and answered: (a) §36 rule 6 is **amended** to say the read is the
effective (clamped) value and a write above the cap is refused — no stored
member; (b) every network 409 body gains a **sub-code** member next to
`error: "conflict"` (`stale_version` / `strands_profile` / `has_children`, exact
names per the code), documented in §36, the console wording the stale case as
"reload"; (c) **R110W6-03 is fixed in 1.1.0**: a `vlan`/`rank`/`enabled` change on
a segment that has a reply profile also needs `network:grant` at the segment,
and H5's quarantine rule on a quarantine segment. One Opus executor on this
branch before the merge.

**Head `122b9ea92`** on `claude/release-1.1.0-w6` (from `3d011573e`), 2026-10-16. The wave has eighteen commits, all signed:
- eleven task commits: W6.1 … W6.6, W6.3b, the renames, and W6.8's two;
- the F4 review;
- six in-wave fixes: R110W6-01 and -03, the coverage matrix, the `409` sub-code, rule 6, and the delete gate.

The three numbers that changed during the wave:
- **Schema:** v100 only. v99 is W1's; the runner applies every version above the highest recorded one, and the newest-version assertion says 100.
- **Registry:** **202 operations / 29 namespaces** (from 190 / 28).
- **Threat model:** **487 entries: 454 Mitigated / 23 Open / 10 Not applicable** (from 477: 443 / 19 / 15).

**D-4, by the orchestrator:** none needed. The D4 e2e (`a_decision_per_authentication_places_revokes_and_quarantines`) ran on this machine with exit 0 (2 passed, 418 s), and the dispatch of `radius-e2e.yml` waits for the merged branch (W8.1).

| Task | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W6.1 | `ef3f1ed0d` | Sonnet | The data model and v100. <br>• Tables `network_segment`, `reply_profile`, `network_policy`, in `TENANT_PURGE_ORDER`. <br>• A segment is a resource row plus a sidecar with the same id, written in one transaction. <br>• `/network`, branch and site nodes have deterministic v5 ids. <br>• The `axiam-radius-reply/1` dictionary is a compile-time table; `ReplyProfileInput` has `deny_unknown_fields`. <br>• Nine `network:*` permissions, all human-only. <br>• The cap `network.session_timeout_max_secs` (default 3600, range 300 … 86400) lives in its own `network_policy` row, not in `security_settings`, which is wire-visible. It is clamped at read. <br>*Tree:* the runner tolerates a version gap (an ordered static list, applying versions above the highest recorded), so v100 after v98 is sound on this branch. |
| W6.2 | `e9766ce35` | Opus | `axiam-authz` `network_gate`. <br>• H1 … H6, rules 1 … 3, the §5.3 rows, reserved names and resources, the subject scope. <br>• The clearance token can be minted only by the gate. <br>• Gated: roles, permissions, certificate bind, the generic resource routes, UMA register/update/delete. <br>• The enumeration test (a source scan plus a token pin) fails if the bind gate is removed. <br>• Seeded roles: super-admin keeps `network:read` and five meta permissions, and never `join`/`admin`/`grant_admin`. Boot reconcile takes back W6.1's grant, and the seeded admin can no longer assign super-admin. <br>• H3 refusals are `403`. <br>*Residuals recorded for W6.7:* the gate and the write are not one transaction (T-481, Open); org-scope meta permissions (T-483, Open); no success gate row (T-484, Open); H6 not applied to role assignment (became R110W6-01). |
| W6.3 | `d741349b3` | Sonnet | Segment and profile routes. <br>• Write order: body → gate → reactor veto (`network.pre_*_write`, fail-closed) → conditional write → audit (`*.write_refused` with the internal rule). <br>• `network_admin_per_min` (default 30), one bucket per write route. <br>• The registry goes from 190 to 200 operations and gains a 29th namespace. <br>*Tree:* the plan named no writer for the tenant cap. Asked, and answered by W6.3b. |
| W6.4 | `fae9d87a5` | Opus | `POST /api/v1/network/decide`. <br>• Callers: cnf-bound service-account tokens only, via `permissions::CERTIFICATE_BOUND_MACHINE_ROUTES`; the network family otherwise stays human-only. <br>• Limits: `network_decide_per_min` 6000 keyed on `sub`, spent before any read, plus a ×10 per-address backstop. <br>• The route is excluded from the registry (§27.0). <br>• Tunnel-Type and Medium-Type carry tag 0; Tunnel-Private-Group-Id carries none. The design note's three "tag `0x00`" lines are corrected with a date (W5.4's finding). <br>• 12 tests, including timing medians within 1.5× and a mutation that drops the ratio to 0.59. <br>*Tree:* `DeviceAuthService` is in `axiam-pki` `mtls.rs`; there is no v101, because the existing audit indexes suffice. |
| W6.3b | `f479c6530` | Sonnet | `GET`/`PUT /api/v1/network/policy`. <br>• The cap is gated and conditional on the version read. <br>• Audit actions: `raised`, `lowered`, `unchanged`, `write_refused`. <br>• Registry **202 / 29**. <br>*Tree:* `network:admin` (the first answer) is not grantable, so the route was writable by nobody. The maintainer corrected the writer to `network:segments_write` at the root. |
| fix | `2b0f0cc1c` | Sonnet | The cap is written with `network:segments_write` at `/network`; the `NETWORK_POLICY_WRITE` alias is removed. |
| W6.5 | `e4dca2686` | Sonnet | The `rlm_rest` recipe. <br>• `freeradius.md` gains §5 D4: mTLS must end at AXIAM (L4 pass-through is fine); the token comes from `POST /api/v1/auth/device`; the request body is closed; the attribute-mapping table; latency; the operator's residuals. <br>• `docker-compose.radius-d4.yml` overrides the base compose file and has no image line. `docker/radius/raddb/d4/` holds the D4 configuration. <br>• The e2e covers: placement, a cached token, an unbound certificate, revocation at the next authentication, quarantine, a wrong site key (`403`), AXIAM down, and 18 non-allow answers that are never copied into the Accept. <br>*Tree:* FreeRADIUS 3.2.8 exposes no client-certificate attribute in the outer post-auth, so the decision runs in `check-eap-tls` post-auth, with a `verify{client}` hook that stashes the SHA-256 by serial. FreeRADIUS has no JSON decoding, so the answer is parsed with one regex per attribute. |
| W6.6 | `acda86038` | Opus | Contract §36: 36.1 … 36.10 are the SDK surface (human-only); 36.11, the decision, is not SDK work, and rule 6 fixes the answer's shape and member order. <br>Threat model: <br>• T-457, T-461, T-463, T-464 and T-468 go from Not applicable to Mitigated. <br>• T-462 stays Open and gains a D4 column. <br>• New T-478 … T-487. <br>• Diagram 9 is updated. <br>*Tree:* 12 operations, not 10. A `403` carries the permission and the node; the rule goes to the audit row only. |
| renames | `70c8039cf` | Sonnet | Maintainer answers (2) and (3): <br>• nine components get network/radius names (`NetworkReplyProfile`, `RadiusServiceType`, `RadiusTerminationAction`, …); <br>• `RadiusServiceType` is a hand-written schema enum, `["framed_user"]`, and the Rust enum keeps the admin variants so that they answer `400`. <br>§36 gains `replace_*` and the manifest namespace. |
| W6.8 | `e4f8c4740` | Sonnet | Console "Network access": the cap panel, segments by kind and site, the typed profile dialog, `403` with permission and node, `409` worded "reload". The decision route is not called. Coverage 96.57%. |
| W6.8 | `326a8072d` | Sonnet | W3's touches: the `422 scope_exceeds_ceiling` message on the client forms, and the notice that a confidential client holding the device grant must authenticate at both device endpoints. <br>*Tree:* the console's grant list has no device-code entry, and a DCR/CIMD client opens read-only, so the `422` is unreachable from those rows today. |
| W6.7 | `dacca3318` | Opus | `claude_dev/security-review-release-1.1.0-w6-2026-10-16.md`: **R110W6-01 Medium**; R110W6-02 … -08 and -13 Low; -09 … -12 Informational. |
| fix | `21ab64fbc` | Opus | **R110W6-01**: H6 also refuses a §5.3 write that widens the writer's own placement — role assign and unassign (including group), role delete, permission grant and revoke. It reads `subject_group_ids`. T-482 → Mitigated; totals 487 / 454 / 23 / 10. |
| fix | `22fcc5098` | Sonnet | **R110W6-13**: the frontend coverage matrix has rows for `network.rs` and `network_decide.rs`, so `docs-ci` is green. |
| fix | `9dff2aa97` | Opus | **R110W6-03** (maintainer (c)): a `vlan_id`/`rank`/`enabled` change on a profiled segment needs `network:grant` at it (`H2:placement`), plus `H5:placement` on quarantine. The `freeze_profiled_placement` clearance narrows the write, and the transaction re-reads, so a race gets `409 stale_version`. The profile transaction writes the segment row (`profile_epoch`). T-478 corrected. |
| fix | `f15f67434` | Sonnet | Maintainer (b): every network `409` carries `reason_code`: `stale_version`, `strands_profile`, `has_children`, `site_gone`, `duplicate_name`/`_vlan`/`_rank`, `profile_exists`, `other`. Documented in §36.3 rule 2, §36.4 and §36.8; the console words the stale case as "reload". |
| fix | `b3a035413` | Sonnet | Maintainer (a): §36.3 rule 6 says a read is the effective (clamped) value, and that writing a clamped read back stores the cap, not the earlier timeout. There is no stored member. |
| fix | `122b9ea92` | Opus | Maintainer, "gate delete too": deleting a profiled segment, or a segment's profile, needs `network:grant` at the segment (`H2:placement`), plus `H5:placement` on quarantine, then H6. The delete transaction re-reads the profile, so a race gets `409 stale_version`; the race test uses surrealkv. Design note §5.2/§4.2, §36.3 rules 1 and 2, the OpenAPI texts, T-478 and the console are updated. <br>*Tree:* neither delete asked H6 before this commit; it is added after the placing right. |

**Filed on `1.1.x`:** ilpanich/axiam#700 (R110W6-02), #701 … #707 (R110W6-04 … -10), #708 (R110W6-14), #709 (R110W6-15).
- #708 is the executor follow-up from `f15f674`: `reason_code` is derived by matching the repository's message text.
- #709 is the follow-up from `122b9ea`: the console offers the profile editor without `network:grant`, and `PLACEMENT_RACED` is misnamed.
- R110W6-11 is fixed at the W6 merge; R110W6-12 is W7.1's and W8.3's.

Accepted as is: a profile delete by a writer without the grant answers `403` before `404`, as every other gated write does (permission before existence).

**For W7.1:**
- §34.6 item (l) counts the network operations from the registry (202 / 29);
- the §27 rows, the §27.0 exclusion table (five → six), §27.4 rule 5 (seven `replace_*`), the §27.6 `network` namespace;
- R110W6-12's contract part.

**For W8.3:**
- the design note's header ("nothing is built") and §3.1;
- `freeradius.md`'s "Which threat-model entries" paragraph and `:866-868`;
- `threat-modeling-and-security.md`, the model version and the website prose;
- the 190 / 28 counts in `website/src` (`data.ts`, `reference.ts`, `integrate.ts`, `security.ts`);
- `operate.ts:~1019`, D3-only text;
- T-444, made stale by the W4 merge, below.

**For W8.4:**
- the `network:*` permissions and the two settings (`network_admin_per_min`, `network_decide_per_min`) as upgrade notes;
- seeded permission descriptions reach existing tenants only through boot reconcile.

### 13.7 W7 — the contract, the eleven SDKs and the conformance review

**The merge into `claude/release-1.1.0` (2026-10-16, by the orchestrator; W4 and
W6 by an Opus merge executor each, since both needed code to reconcile).** Six
signed merge commits, pushed:

| Wave | Merge | Conflicts and how they were resolved |
|---|---|---|
| W1 | `764fe02d7` | none |
| W2 | `8cb95aa9a` | T-102 (STRIDE and Threat Dragon): W1's #615/#616 and W2's #654 amendments both kept, W1's first (word-level three-way merge) |
| W3 | `45243b94d` | `rate_limit.rs` imports (union); `cleanup.rs` and `cleanup_task.rs` keep W1's `certificate_retention` and W3's `rate_limit_bucket` sweeps; the tenant-purge entry keeps #622 then #637; `operate.ts` lists 23 sweeps (24 with the revocation feed); spec and registry deferred to the W6 merge |
| W4 | `7292eaf56` | W1's orphan claim marker (#622) inside W4's two-phase purge (#655): `begin_orphan_purge` / `purge_orphan_rows` / `remove_purged_tenant`, the orphan unit under W4's `PurgeClaim` (released, not dropped, when given up, so the tombstone sweep finishes it); `ErasureUnit` carries #618's (b4). Also `tenant_purge_test.rs`: two W3 literals gain W1's `orphan: false` (the W3 merge did not compile there). Gate: fmt, clippy both feature sets, `tenant_purge_test` 11, `cleanup_task` 40, `axiam-db --lib tenant` 24, all 0 |
| W5 | `a6c6340fa` | `freeradius.md`'s Ed25519 bullet: W1 (#651, keys returned as PKCS#8 v1), W5's re-encoding recipe dropped as obsolete. **Correction:** the merge body attributes the recipe to #644; it is **#647** (R101W6-08), which closes as superseded by #651 |
| W6 | `09350bd2f` | migrations 98, 99, 100 (assertion 100); both limiter backstops; both sizing rows; `radius-e2e.yml` filters united plus W5's script step; both e2e tests; the T-462 row in W6's D3/D4 form with W5's amendment; spec, registry (202 / 29) and `threatModel.ts` regenerated. Fixes the merged tree needed: `unprocessable_entity()` sets `reason_code: None`; the D4 e2e calls W5's six-argument `refresh_crl` with a mirror; the v99 re-apply test deletes `version >= 99`; the enumeration test's exemption names W4's `cleanup.rs::prepare`. **R110W6-11** fixed (`freeradius.md`, `axiam-d4.sh`: serials are unique per issuer). Gate: workspace fmt and clippy `-D warnings` (SAML off; api-rest with SAML on), `axiam-db --lib` 302, the network, certificate, seeder and purge binaries, `axiam-authz --lib` 128, `axiam-api-rest --lib` 305 and the rate-limit binaries, the e2e compiled, every `scripts/check-*` 0 but `check-website-links` (proxy 403) and `check-sdk-artifact-drift` (until W7 re-vendors), console and website `tsc`/lint/vitest 0 |

Threat model after the merge: 487 — 454 Mitigated / 23 Open / 10 Not
applicable, version still 2.41.0 (W8.3 takes it to 2.42.0). **For W8.3, from
the merges:** T-444 is stale after the W4 merge (an orphan purge now has a point
of no return, the marker's removal, and one given up leaves the marker for the
tombstone sweep); T-462 dropped "the recipe does not call AXIAM per
authentication" (false with D4); the guide's D3 placement table writes the VLAN
attributes untagged while §13.5 says W5.4 tagged them — check against the wire
(W5.4's measurement) and make one statement; the guide's §4 must say a "lower
than the installed" CRL refusal is expected once after an interval change and
link the PKI README's rule (§13.5); the STRIDE text and `freeradius.md` still
say all four Mitigated RADIUS entries are tested by the e2e.


**W7, after the merge (2026-10-16).** Every commit is signed and pushed to
`claude/release-1.1.0` unless the row says otherwise.

| Item | Commit | Model | What landed; where the tree overruled the plan |
|---|---|---|---|
| W7.1 | `5c012d741` | Sonnet | Contract 1.62 record §34.6 (a) … (s). <br>• Added: §27.6.2, the `network` manifest namespace. <br>• §14.1/§14.2 rewritten for option (a) and R110W3-11's stale text. <br>• Counts: the registry is unchanged at 202 operations / 29 namespaces; 11 `replace_*`, 18 sparse, 26 paginated. <br>*Plan vs tree:* <br>• **eleven** `replace_*` operations, not the "seven" of §13.6, because §27.4 rule 5 had been stale since 1.51; <br>• twelve network operations, not ten; <br>• the historical 190/28 counts kept, with "202/29 since 1.62" beside them. <br>The OpenAPI description of `RadiusServiceType` says the admin values are refused with `400`, but the code answers `403` (#700; for W8.2). It recorded ten questions. |
| W7.1b | `d76c5a80b` | Sonnet | The maintainer's answers to four of those questions (2026-10-16): <br>• the device grant sends client secrets in the form body only, never `Authorization: Basic` (§12.1 rule 3 stands); <br>• a clamped profile is judged on the read; <br>• `filter_ids` are compared as a set; <br>• `kind` uses the wire spelling, `access` or `quarantine`. <br>Also: §27.4 rule 4 counts 26 paginated operations. An above-cap timeout is a `403 authorization_denied` (H3). |
| W8.4a | `89e488e3e` | Sonnet | **Version 1.1.0, moved forward from W8.4** so the SDKs re-vendor the final spec once. Changed: the workspace and its pins, the console's version label, the k8s image tags, `Cargo.lock`, `openapi.json` (`info.version` only; digest `cf0fc71c…59a7`), the registry and `apiIndex.ts`. Left for W8.4: CHANGELOG, `version.ts`, the news post. |
| SDK ports W7.2 … W7.12 | see below | Sonnet ×11 | Each SDK vendors `d76c5a80b` and is at 1.1.0, with `[1.0.1]` folded into `[1.1.0]`. Each adds: <br>• the twelve network operations (no method for the decide route); <br>• the `network` manifest namespace; <br>• the change-taking SSF form; <br>• device-grant credentials in the form body; <br>• its §8.2 extras. |
| W7.13 | `3da7e0c9c` | Opus | `claude_dev/sdk-contract-1.62-conformance-review.md`: 0 High / 3 Medium / 6 Low / 8 Informational, and ten questions for the maintainer in §5. <br>• **Medium:** C162-01 (C) and C162-02 (C++), where caller-allocated structs grew with `SOVERSION` still 1; C162-03 (PHP), where unseen SSF event-type URIs were blanked. <br>• **Ruling:** the §21.9 DPoP rows were wrong, not the SDKs; no SDK generates proofs. |
| W7.1c | `d25413506` | Sonnet | The maintainer's answers to the review's §5 (2026-10-16): <br>• Q10/C162-14 corrections: §21.9's seven rows; §27.2 rule 1 (19/19 of 29); §27.10 and §36.10. <br>• Q6: a §36 Conformance Statement sentence. <br>• Q5: pruning is a MAY; §27.10 records "no pruning" for all eleven. <br>• Q1: no session or adopted credential on any `/oauth2/*` request. The exception, written by the executor and accepted, is a credential the caller passes to that one call (RFC 7591/7592 registration tokens, §28.12). <br>• Q2: an unknown enum value on an unstated member is refused at `plan`, before any write; only an `Update` is refused. <br>• Q3: `termination_action`, `enabled` and `filter_ids` cannot be stated as none. <br>• Q8 and Q9 confirmed as written. <br>• Q4 (SCIM (g)) and Q7 (producer refusal) deferred to 1.63. |
| W7.14 fix pass | see below | Sonnet ×11 | **Every SDK:** <br>• re-vendors `d25413506`; <br>• its README names §36 and says "manifest pruning: not offered in any namespace". <br>**Per finding:** <br>• **C162-01:** C goes to `SOVERSION 2`, with the `abi_soname` test. <br>• **C162-02:** C++ goes to `SOVERSION 2`, with the `abi_soname` test (shared builds only). <br>• **C162-03:** PHP emits `list<SsfEventType|string>`, with four round-trip tests. <br>• **C162-05 (maintainer: fix now):** TypeScript, Python, Java, C# and Kotlin withhold the session or adopted bearer on `/oauth2/*`. Rust, Go and Swift already did, and gain regression tests. |

**The eleven SDK pull requests** (draft, branch `claude/contract-1.62`). The head is the fix-pass commit.

| SDK | PR | Port head | Fix-pass head | CI on the fix head |
|---|---|---|---|---|
| Rust | ilpanich/axiam-rust-sdk#131 | `4c02dc1` (CodeQL fix after `bd362f6`) | `ba61dd4` | pending |
| TypeScript | ilpanich/axiam-typescript-sdk#141 | `973427c` | `a9f7140` | green |
| Python | ilpanich/axiam-python-sdk#98 | `71db0de` | `d5594cd` | green |
| Go | ilpanich/axiam-go-sdk#98 | `5ebfb22` | `e3bf7b3` | green |
| Java | ilpanich/axiam-java-sdk#114 | `dfcc1eb` | `3da7142` | green |
| PHP | ilpanich/axiam-php-sdk#83 | `7a238fa` | `d363c66` | green |
| Kotlin | ilpanich/axiam-kotlin-sdk#76 | `07855aa` | `7f0c68b` | pending |
| C# | ilpanich/axiam-csharp-sdk#106 | `f70d039` | `1aab662` | green |
| C | ilpanich/axiam-c-sdk#73 | `18be8e1` | `6a60bd0` | green |
| C++ | ilpanich/axiam-cplusplus-sdk#75 | `d3670ed` | `5d9764b` | green |
| Swift | ilpanich/axiam-swift-sdk#74 | `4d34370` | `66660bc` | pending |

**Filed on `1.1.x`.**
- **SDK repositories:** the review's Low and Informational findings, one issue per SDK.
  - rust#132 (C162-07, -13), typescript#142 (-07, -08), python#99 (-07, -08), go#99 (-07), java#115 (-07, -10), php#84 (-04, -07), kotlin#77 (-07, -10), csharp#107 (-06, -15), c#74 (-06, -09), cplusplus#76 (-07, -16), swift#75 (-17).
  - python#100: an adopted bearer overwrites an explicit PAT on `/uma2/*`.
- **Platform:** ilpanich/axiam#710 covers the 1.63 contract items. Session cookies and `X-CSRF-Token` still reach `/oauth2/*` after a cookie login (Rust, Python and others); also the deferred Q4 and Q7.

**Plan vs tree:**
- §8's version rule: superseded by D-2 amended (all eleven SDKs at 1.1.0).
- The platform version bump: moved from W8.4 into W7 (W8.4a).
- W7.13: followed by a second contract commit (W7.1c) and a fix pass (W7.14) that the plan did not foresee. The review's questions needed answers that changed contract text, so the SDKs re-vendored once more, all eleven together.

**Environment:**
- Neither .NET nor Swift was preinstalled; the C# executors installed .NET 8 and 10 from apt.
- Swift was never compiled locally. Its only builds are the PR's CI, which passed on the port head.
- A Maven Central mirror init script under `~/.gradle/init.d/` (sandbox-only) was needed for Gradle.
- Two stray log files at the filesystem root (`/scratchpad.log`, `/scratchpad_gen.log`) could not be deleted by the session's safety check; the maintainer removes them.

### 13.8 W8 — release readiness

All W8 commits are signed and pushed to `claude/release-1.1.0`. The release pull request is
**ilpanich/axiam#716** (non-draft, base `main`).

| Item | Commit | Model | Result |
|---|---|---|---|
| W8.1 | — (a check; nothing committed) | Sonnet | Regression gate on `310203c98`, 3 h. <br>**Passed (exit 0):** <br>• `fmt`; workspace `clippy -D warnings` with SAML on and off. <br>• **7 250 Rust tests passed, 0 failed, 38 ignored** (1.0.1 also had 38 ignored), run crate by crate. `axiam-db`, `axiam-api-rest` and `axiam-server` ran one binary at a time: 78, 113 and 27 runs. <br>• The `client`-feature gRPC tests (34) and the conformance leg (14). <br>• **The RADIUS e2e, run locally: D3 and D4 passed** (425 s); `fetch-crl-test.sh` 64/64 under dash and under bash. <br>• Every `scripts/check-*` and its self-test, except the three below. <br>• Frontend lint, `tsc`, a11y and build; vitest 2 376 tests at 96.57 % coverage. Two `ScimTargetsPage` tests timed out under load on the first run and passed alone and on the rerun. <br>• Website lint, `tsc` and build; `npm audit` 0. <br>**Failed:** `cargo deny` and `cargo audit` on rustls 0.23.45 (RUSTSEC-2026-0346 … -0349), already on `main`; fixed in W8.1a. <br>**Expected failures:** `check-website-links` (the proxy returns 403), `check-sdk-artifact-drift` (until the SDK PRs merge), `check-sdk-amqps` (no SDK clone beside the checkout). <br>**Not run here:** the SurrealDB container (Docker Hub 429), the live AMQP broker, Playwright, Trivy, hadolint and llvm-cov. |
| W8.1a | `f922935a0` | Sonnet | rustls 0.23.46 and yoke-derive 0.8.4, in three lockfiles: workspace, `examples/b3-mesh-delegation-grpc`, `tools/surreal-race-probe`. `cargo deny`, `cargo audit` (CI's ignores) and `clippy` pass; 81 runs of the rustls-touching test binaries pass. The Rust SDK already had 0.23.46. |
| W8.2 | `f17af4c8f` | Opus | `claude_dev/security-review-release-1.1.0-2026-10-16.md`: **0 Critical / 0 High / 0 Medium**, 2 Low, 3 Informational, all filed on `1.1.x`: <br>• R110-01 #711: with no appending proxy, the per-address limiters key on a caller-written `X-Forwarded-For`. <br>• R110-02 #712: the #675 boot count re-runs its subquery per row. <br>• R110-03 #713, R110-04 #714, R110-05 #715. <br>Found sound: the W1×W4 purge merge, the limiter merges, v99/v100, the decide route against device tokens, the serial-keyed stash, W6's six late commits, the W7 contract text. All 97 commits are signed. |
| W8.3 | `e8bf77fd1` | Opus | **Model 2.42.0**; the five copies agree. **487 threats: 454 Mitigated / 23 Open / 10 Not applicable** (Critical 43/2/0, High 201/9/6, Medium 204/8/3, Low 39/4/1). <br>• Corrected entries: T-444, T-472, T-462, T-212, T-486, T-481, T-483, T-484, T-478, plus the RADIUS diagram description. <br>• Guides: `freeradius.md` §4 and §5; the deployment guide's "Direct, no proxy" row; the design note's header. <br>• Website: the 202/29 counts. |
| W8.4a | `89e488e3e` | Sonnet | Version 1.1.0; done in W7 (§13.7). |
| W8.4 | `4890fa37e` | Sonnet | CHANGELOG: <br>• `[1.0.1]` folded into **`[1.1.0] - 2026-10-16`**, every entry kept. <br>• One entry per closed issue (43). #626, #629 and #647 are marked done or superseded; #675's entry says the issue stays open. <br>• An "Upgrading to 1.1.0" subsection lists the operator-first notes. Stale 1.0.1 text is corrected in place. <br>Website: an `axiam-1-1-0` post. <br>PR #716 is on #657's shape, with 43 `Closes` lines and the eleven SDK PRs listed. |

**Corrections to §13.7.**
- **The W5 merge (`a6c6340fa`) dropped most of W5's changes to `docs/pki/freeradius.md`,** not only the Ed25519 bullet. It resolved the one conflicting hunk by taking the whole file from the plan side. The lost text was:
  - the `fetch-crl.sh` documentation;
  - the `ca.pem` replacement rules;
  - the NAS half of Blast-RADIUS;
  - the tagged placement table;
  - R110W5-01 … -03.

  W8.3 found the loss and restored the text by a three-way merge in `e8bf77fd1`. The orchestrator verified that every line W5 added is present again, except the key re-encoding recipe, which was dropped on purpose as obsolete, and the "Last verified" date, which was updated. W5's threat-model text and W5's other files were never affected.
- **The W5 merge commit names #644 for the re-encoding recipe; it is #647** (already recorded in §13.7).
- **`89e488e3e` carries `Co-Authored-By: Claude Sonnet 5.5`** instead of the verbatim trailer line the executor rules give. It is pushed, so it is recorded here, not amended.

**Left for the maintainer.**
- `website/src/version.ts` `SECURITY_VERIFIED_RELEASE`/`_DATE` stay at 1.0.1 / 2026-10-14. W8.3 reconciled the Security section; it did not re-derive it from source. Moving the stamp would assert a verification nobody made; it is a one-line change once the maintainer judges it.
- #700: is an administrative `Service-Type` refused with `400` or `403`? The code and contract say 403; the spec's description says 400. Open on `1.1.x`.
- The two stray log files at the filesystem root of the build sandbox (`/scratchpad.log`, `/scratchpad_gen.log`). They are outside the repository; the session's safety check refused their removal.

**Hand-off (nothing is tagged or merged by Claude).**
1. Merge PR #716.
2. Mark the eleven SDK PRs ready and merge them; their drift check compares with AXIAM `main`:
   - ilpanich/axiam-rust-sdk#131 `cde52e0`
   - axiam-typescript-sdk#141 `a9f7140`
   - axiam-python-sdk#98 `d5594cd`
   - axiam-go-sdk#98 `e3bf7b3`
   - axiam-java-sdk#114 `3da7142`
   - axiam-php-sdk#83 `d363c66`
   - axiam-kotlin-sdk#76 `7f0c68b`
   - axiam-csharp-sdk#106 `1aab662`
   - axiam-c-sdk#73 `6a60bd0`
   - axiam-cplusplus-sdk#75 `5d9764b`
   - axiam-swift-sdk#74 `66660bc`
3. Tag `v1.1.0` on the platform and on all eleven SDKs.

The 43 issues close with the PR. 52 stay open on `1.1.x` (#664 … #715) and 2 on `1.0.x` (#513, #561).

**§13.8 addendum — CI on PR #716.** Five commits fixed what CI found on the release pull request. All are signed and pushed to `claude/release-1.1.0`.

| Commit | What failed | Root cause | Fix |
|---|---|---|---|
| `39493eff8` | Clippy on Rust 1.99: `result_large_err`. | `GateRefusal` was 152 bytes; the lint's threshold is 128. | `GateRefusal::missing` is boxed. The type is now 120 bytes. |
| `e9e7cb93a` | E2E nav-reach matrix, `nav-reach.spec.ts:197`. | The `/network` route that W6.8 added was missing from `NAV_DESTINATIONS`. | One row in `frontend/e2e/helpers/matrix.ts`. |
| `057a9c5a2` | CodeQL `rust/cleartext-logging` (high), at `certificate_test.rs:1502`. | Assertion messages formatted certificate subjects, fingerprints, key-bearing bodies, client secrets and token responses. | The messages in 10 test files no longer format them. The assertions are unchanged. <br>*Follow-up:* #717 (`vault_ca_key_store_test.rs`, which is outside the release's change list). |
| `4ec6aca7b` | "No space left on device" in the Test job and the cargo-llvm-cov job. | After `cargo test --workspace`, `target/` was 104 GB on a 145 GB runner. | • More preinstalled toolchains are freed. <br>• `ci.yml` drops test executables that have already run. <br>• `coverage.yml` cleans the profraw files and instrumented binaries after the Coveralls upload. <br>Measured afterwards: 117 GB free. |
| `67bc4c464` | `network_routes_test` got 429 instead of 409 or 200. It failed 3 runs in 30 locally, whenever a run crossed a minute boundary. | The shared rate-limit counter seeds a cold entry: for a key first seen mid-minute, up to 90 % of a limit of 20 or more. | The contract tests turn the shared counter off. The limiter test keeps both layers. <br>*Follow-up:* #718. The same seed affects production admins of every 30/min family; whether to change it is a maintainer decision. |

**Security Scan, not fixed in the PR.** Three RustSec advisories on `zip` 8.6.0 (RUSTSEC-2026-0367 high, -0368, -0369 critical) were published on 2026-10-16 at 19:44 UTC. `zip` is a `[build-dependencies]` entry of `utoipa-swagger-ui` 10.0.1 (the latest release, `zip = "8.6"`), so there is no upgrade path, and `main` is red on the same three. The build script does not call `extract()`, and none of it ships in the binary. The decision, to ignore the advisories with a rationale or to fork or vendor `utoipa-swagger-ui`, is the maintainer's. It was posted on the PR on 2026-10-17 and is open at the time of writing.

Final CI state on `67bc4c464`: every check is green except Security Scan, including Test, cargo-llvm-cov, E2E, CodeQL Analyze (rust) and the runtime smoke.

---

## 14. Kickoff prompts

### Orchestrator

> Read `CLAUDE.md`, `claude_dev/release-1.1.0-plan.md` in full, and the six
> 1.0.1 review documents its issues cite
> (`claude_dev/security-review-release-1.0.1-w1-2026-10-13.md`, `…-w2-…`,
> `…-w3-…`, `…-w4-…`, `…-w6-…`, `claude_dev/security-review-release-1.0.1-2026-10-14.md`).
> D-1 … D-6 are answered in §11 (2026-10-14): do not ask them again.
> §12 is settled: never re-open a question it answers. Run W1 … W6 as
> independent branches from `main`, each item by one executor at the model
> its row names, each wave ending with its F4 review; then W7 on the merged
> plan branch (eleven SDK sessions in parallel, then the conformance review);
> then W8. Record every wave in §13 as it lands. Re-size and re-model by §1.1
> whenever an executor stops short, and say so in §13.

### W1

> Read `CLAUDE.md`, the plan §0–§2 and §10, and the 1.0.1 W1 review
> (`claude_dev/security-review-release-1.0.1-w1-2026-10-13.md`) §12 and the
> combined review's R101-02 … R101-05. Check out `claude/release-1.1.0-w1`
> from `main`. Execute W1.1 … W1.11 in order, one signed commit per item,
> each with the tests its row names, v99 (W1.9, only if the index is absent)
> with its scope test and the newest-version bump, and its threat-model entry
> in the same commit; run the §10 gate before each commit and `cargo clean`
> between items. End with the F4 review of the wave diff; fix Medium and
> higher in the wave, file Low and Informational on the next patch milestone.
> Record the head in §13.1.

### W2

> Read `CLAUDE.md`, the plan §0–§1, §3 and §10, and the 1.0.1 W2 review §12
> and the combined review's R101-02. Check out `claude/release-1.1.0-w2` from
> `main`. Install `libxml2-dev` and `libxmlsec1-dev`; run the `build-no-saml`
> `cargo check` before every commit as well as the gate. Execute W2.1 … W2.4
> in order (W2.3 records its D-3 choice in the commit body). End with the F4
> review; record the head in §13.2.

### W3

> Read `CLAUDE.md`, the plan §0–§1, §4 and §10, and the 1.0.1 W3 review §13.
> Check out `claude/release-1.1.0-w3` from `main`. Execute W3.1 … W3.8 in
> order; W3.1 first, because W3.7(a) folds into it. W3.8 regenerates
> `sdks/openapi.json` (the §10 build steps). End with the F4 review; record
> the head and W3.8(e)'s bench number in §13.3.

### W4

> Read `CLAUDE.md`, the plan §0–§1, §5 and §10, the 1.0.1 W4 review §12 and
> the combined review's R101-03. Check out `claude/release-1.1.0-w4` from
> `main`. W4.1 is two issue comments, no code. Execute W4.2 … W4.7; W4.5 and
> W4.6 need a `workflow_dispatch` (D-4). End with the F4 review; record the
> head in §13.4.

### W5

> Read `CLAUDE.md`, the plan §0–§1, §6 and §10, the 1.0.1 W6 review §12 and
> `docs/pki/freeradius.md` in full. Check out `claude/release-1.1.0-w5` from
> `main`. Bring up `docker/docker-compose.radius.yml` and run `radius_e2e.rs`
> before the first change (a green baseline). Execute W5.1 … W5.4; W5.2 reads
> W1.10's outcome from §13.1 if W1 has landed, else keeps the workaround with
> the `umask` fix. End with the F4 review; record the head in §13.5.

### W6

> Read `CLAUDE.md`, the plan §0–§1, §7, §10 and D-5, D-6;
> `claude_dev/radius-reply-profile-design.md` in full;
> `claude_dev/radius-eap-tls-spike-2026-10-06.md` §5.2 and §6; and the 1.0.1
> W6 review. Check out `claude/release-1.1.0-w6` from `main`. Execute W6.1 …
> W6.6 in order: v100 … v102 with their scope tests; W6.2 before any route
> exists; W6.3 regenerates `sdks/openapi.json` and `management-registry.json`;
> W6.4 at Opus. Stop at a clean commit and report if W6.2 or W6.4 is larger
> than L. End with the F4 review (W6.7), which reads H1–H6 and §5.3 against
> the code; record the head in §13.6.

### W7

> Read `CLAUDE.md`, the plan §8, §10 and §12, `sdks/CONTRACT.md` §27, §32,
> §33, §34.5 and §36, and `claude_dev/sdk-contract-1.61-conformance-review.md`.
> On the plan branch, execute W7.1 (the §34.6 record, every item (a) … (l);
> regenerate the spec and the registry). Then, one session per SDK in
> parallel, W7.2 … W7.12 on `claude/contract-1.62` in each SDK repository,
> each a draft PR vendoring the plan branch byte for byte, with the per-SDK
> extras of §8.2 and the version of §8's rule. Then W7.13, the conformance
> review, at Opus; fix Medium and higher in the SDK PRs. Record the heads and
> the PR numbers in §13.7.

### W8

> Read `CLAUDE.md` and the plan §9, §10 and §13. On `claude/release-1.1.0`,
> run W8.1 with every exit code taken from the tool; then W8.2, the combined
> F4 review, fixing Medium and higher here; then W8.3, the model at 2.42.0;
> then W8.4, the CHANGELOG, the version and the pull request on #657's shape,
> `Closes` for the 43 issues, the eleven SDK PRs listed, and the hand-off
> steps (tags after merge: `v1.1.0` on the platform; `1.2.0` on Rust, Java,
> Kotlin and PHP; `1.1.0` on the other seven). Record everything in §13.8.
