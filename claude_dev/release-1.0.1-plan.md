# Release 1.0.1 plan — closing the open issues after the 1.0.0 tag

> **Status: IN PROGRESS — W1 and W4 landed 2026-10-13 (§11).** Written on 2026-10-12 against `main` at
> `0a90de0` (`chore(release): prepare axiam 1.0.0`). It covers **28 of the 30
> open issues** on `ilpanich/axiam`: the twenty-five Low and Informational
> findings of the 1.0.0 F4 review (#590 … #614), the two deferred non-local
> items (#533, #538) and the RADIUS tracker (#563). **#513** (the conformance
> submissions) and **#561** (benchmark run 6) are the maintainer's and are out of
> scope by decision of 2026-10-12.
>
> **Shape.** Seven waves. W1 … W4 are independent and branch from `main`; W5
> (contract 1.61 and the eleven SDK ports) needs the fields W1, W3 and W4 add;
> W6 (RADIUS option B) is gated by decision D-2; W7 (release readiness) needs
> everything. As for 1.0.0, the waves are merged into one plan branch,
> `claude/release-1.0.1`, and **one pull request** closes every issue on a
> `Closes` line. The eleven SDK repositories get one pull request each.
>
> **Execution.** One **Opus 5.5 orchestrator** session runs the plan. It spawns
> one executor per task at the model the task table names, runs the gate of §9
> before every commit, and ends each wave with an F4 review of the wave diff
> (Opus 5.5). The orchestrator writes code only to resolve a merge; everything
> else is an executor's. Every commit is signed; nothing is closed by hand.
>
> **What the agent does not do.** It does not tag, does not merge, does not run
> the conformance suites, and does not dispatch benchmark runs.

---

## 0. The state, measured (2026-10-12)

Verified on the tree, not taken from the issues. Where an issue and the tree
disagree, the tree wins and the task says so.

| Fact | Measured | Evidence |
|---|---|---|
| Platform version | `1.0.0` in the tree; **no `v1.0.0` tag on `origin`** (latest is `v1.0.0-beta18`) | `Cargo.toml:62`; `git ls-remote --tags origin` |
| CHANGELOG | `## [Unreleased]` empty; `## [1.0.0] - 2026-10-10` promises "security fixes ship in `1.0.x`" | `CHANGELOG.md:9-30` |
| Contract | **1.60**; highest section **§35** (CRL, informative); next free top-level section **§36**; 1.60's record is §34.4 | `sdks/CONTRACT.md:12279,12410` |
| Threat model | **2.40.0**, `threatTop` 475; next free id **T-476** | `ThreatDragonModels/Axiam/Axiam.json`; `claude_dev/threat-model-stride.md:10` |
| Schema | newest migration **v94** (`certificate.vault_revoked_at`); next **v95**; the newest-version assertion must be bumped with each | `crates/axiam-db/src/schema.rs:490-494,4680-4693,6204-6215` |
| Open issues | 30; 28 in scope | GitHub, 2026-10-12 |
| Keycloak in CI | `docker/docker-compose.e2e.yml` (26.7.0), job `e2e` in `.github/workflows/ci.yml:834`, step "T23.2.7 SAML IdP round trip" at `:917` | the workflow |
| `--no-default-features` | the `build-no-saml` job only `cargo check`s; SAML tests run where `libxml2-dev` and `libxmlsec1-dev` are installed | `.github/workflows/ci.yml:41,186,189-205` |

### 0.1 Where the issues and the tree disagree

| # | What the issue says | What the tree says | Consequence |
|---|---|---|---|
| 597 | the open-register prose says "With one exception — T-447" | neither file carries that sentence any more; both read "with no exception" since `6a9047e` (model 2.40.0); T-469 is Mitigated in the model, the STRIDE table and `website/src/security.ts:136` | **No code.** The issue is on the PR's `Closes` line with a one-line comment naming `6a9047e` (W4.1) |
| 594 | `writeln!` issues two `write` calls, so two records can share a line | `append_blocking` builds `line + '\n'` and writes it with one `write_all` (`dead_letter.rs:176-192`); the writer task does the same per batch (`:472`) | the interleave sub-item is dropped; the blocking call, the mode and the missing `fsync` remain (W4.6) |
| 598 | `cleanup_handle.await` at `boot.rs:3141` | now `boot.rs:3270`; the budget comment is at `:3296-3300`, the constants at `:3301-3338` | none |
| 601 | `authenticate_client` at `token.rs:3160` | `token.rs:3184-3222`; the one tenant read on the auth path (`:1220-1231`) runs only for `tls_client_auth` | none |
| 606 | "needs the variant in samael's `AllowedSignatureAlgorithm`" | samael 0.0.22 has **no SHA-1 variant** at all; `None` means "all"; `Some` checks both the `SignatureMethod` and every `DigestMethod` | the fix is an AXIAM-side URI check on the document already parsed at `saml.rs:731`, not a samael list (W2.2) |
| 605 | three `Parser::default()` sites | the three sites hold, and samael's own `reduce_xml_to_signed_with_allowed_algorithms` re-parses with libxml defaults, outside AXIAM's control | the fix closes the three sites and the BOM; the samael re-parse is recorded as the residual of T-474 (W2.1) |
| 614 | "the browser preset applies, since people drive it" | the route sits in the **authenticated** `api_scope` (`server.rs:1816-1830`), and its four siblings (`/federation/saml/acs`, `/metadata`, `/federation/oidc/authorize`, `/callback`) carry no limiter either | W2.4 limits the route the issue names; D-3 asks whether the siblings ride along |
| 590 | `frontend/src/pages/SsfStreamsPage.tsx` | `frontend/src/pages/ssf/SsfStreamsPage.tsx:107-131`; the repository already supports `expected_updated_at` (`ssf_stream.rs:397-413`), so the fix is handler, console and contract | none |
| 599 | `MAX_PENDING_LIST` in `ciba_request.rs:371` | the constant is `crates/axiam-oauth2/src/ciba.rs:771`; the repository query takes a `limit` | none |
| 611(a) | `vault_pki.rs:218` | holds, and three more Vault clients have no redirect policy: `ca_key_store.rs:199`, `main.rs:151` (the bootstrap client handed to the secret provider), `secrets.rs:464` | W1.2 closes all four |

### 0.2 What this plan could not do

- **SAGE** is not connected in the writing session; the plan is built from the
  repository and the issues alone.
- **Milestones** cannot be set from the session's tooling. Every issue in scope
  is already on `1.0.x`; the maintainer creates **`1.0.1`** and moves the 28
  issues when the plan starts.
- **The `v1.0.0` tag** does not exist on `origin` as of 2026-10-12 (§0). The
  plan assumes it is pushed before W1 starts (D-1).

---

## 1. Scope — every open issue, one wave each

| # | Title (short) | Severity as filed | Wave | Task | Size | Model |
|---|---|---|---|---|---|---|
| 609 | CRL distribution point is not the URL validated | Informational | W1 | W1.1 | S | Sonnet 5.5 |
| 611 | Vault client redirects (a); SAML assertion certificate replacement unaudited (b) | Informational | W1 / W2 | W1.2 / W2.3 | S / S | Sonnet 5.5 |
| 607 | CRL route's global lock and per-request read | Low | W1 | W1.3 | M | Opus 5.5 |
| 608 | CRL consistency across replicas and caches | Informational | W1 | W1.4 | M | Opus 5.5 |
| 603 | Vault revocation sweep can starve | Low | W1 | W1.5 | M | Sonnet 5.5 |
| 612 | Revoking a `vault_pki` tenant CA not forwarded to Vault | Low | W1 | W1.6 | L | Opus 5.5 |
| 610 | (a) stale comment, (b) endpoint-level revocation test, (c) sweeps across replicas, (d) client deletion | Informational | W1 / W3 | W1.7 (c), W3.7 (a), W3.8 (b), W3.3 (d) | M / S / M / M | see tasks |
| 533 | Bind certificates to users | Low, not local | W1 | W1.8 | L | Opus 5.5 |
| 605 | UTF-8 refusal does not see past a BOM | Low | W2 | W2.1 | M | Opus 5.5 |
| 606 | SHA-1 escape hatch admits every algorithm | Low | W2 | W2.2 | S | Opus 5.5 |
| 614 | `POST …/federation/saml/authn-request` has no limiter | Informational | W2 | W2.4 | S | Sonnet 5.5 |
| 591 | Federation sends credentials through the redirect-following guard | Low | W2 | W2.5 | M | Sonnet 5.5 |
| 538 | SAML SLO untested against a real SP | Informational, not local | W2 | W2.6 | L | Opus 5.5 |
| 604 | Device-grant redemption does not ask `account_may_act` | Low | W3 | W3.1 | S | Sonnet 5.5 |
| 601 | A tombstoned tenant's clients still authenticate | Low | W3 | W3.2 | M | Sonnet 5.5 |
| 613 | Withdrawn `dcr_allowed_scopes` entry survives on DCR rows | Low | W3 | W3.4 | M | Opus 5.5 |
| 602 | Tenant purge destroys audit rows no export covers | Low | W3 | W3.5 | M | Opus 5.5 |
| 599 | CIBA pending list's bounds | Informational | W3 | W3.6 | M | Sonnet 5.5 |
| 597 | Open-register prose omits T-469 | Informational | W4 | W4.1 | — (already fixed) | Sonnet 5.5 |
| 592 | Conformance workflow's image input reaches `$GITHUB_ENV` | Low | W4 | W4.2 | S | Sonnet 5.5 |
| 593 | Conformance gate cannot see a newly parked module | Low | W4 | W4.3 | M | Sonnet 5.5 |
| 600 | Tenant settings save pins an inherited `false` | Informational | W4 | W4.4 | S | Sonnet 5.5 |
| 590 | SSF streams page reverts a receiver's change | Low | W4 | W4.5 | M | Sonnet 5.5 |
| 594 | GDPR dead-letter path blocks the request path, not durable | Low | W4 | W4.6 | M | Sonnet 5.5 |
| 595 | Dead-letter lines carry no time | Low | W4 | W4.7 | M | Sonnet 5.5 |
| 596 | A refused in-process enqueue writes on the producer's path | Low | W4 | W4.8 | M | Sonnet 5.5 |
| 598 | Two edges of the stop budget | Informational | W4 | W4.9 | M | Opus 5.5 |
| 563 | RADIUS: FreeRADIUS-backend route (option B) | none, "not scheduled" | W6 | W6.1–W6.2 | S + M | Opus / Sonnet |

Out of scope, by decision: **#513**, **#561**.

### 1.1 How the model is chosen

The rule applied to every row, so that the orchestrator can re-derive it when
a task turns out larger than sized:

- **Opus 5.5** where the task *defines* behaviour under adversarial input or
  concurrency (a verifier, a parser, a lock, a sweep that two replicas run), or
  where it spans a schema migration plus three or more crates, or where the
  issue proposes two designs and the executor has to choose on the evidence in
  the tree. Every F4 review and the orchestrator are Opus 5.5.
- **Sonnet 5.5** where the issue already states the fix, the tree holds a
  precedent at a named `file:line`, and the oracle is a test the issue names.
  Most of W4, the SDK ports and the FreeRADIUS recipe are of this kind.

Expected cost, counted in executor sessions: W1 8–10 (six Opus), W2 7–9 (four
Opus), W3 7–8 (three Opus), W4 6–7 (one Opus), W5 5–7 (none), W6 3–4 (one),
W7 2–3 (two). Roughly **38–48 sessions, 17 of them Opus**, plus the
orchestrator. #538 and #533 are the two long poles; both may be re-sized by
their first session.

---

## 2. Wave W1 — PKI, CRL and Vault (branch `claude/release-1.0.1-w1`)

**The one wave that touches `crates/axiam-db/src/schema.rs`.** Migrations
are numbered here so that no other branch competes for a version: v95 (W1.5),
v96 (W1.6), v97 (W1.7), v98 (W1.8). Each lands with a `vNN_adds_only_…` scope
test and the newest-version bump, as v94 did (`schema.rs:4725,6204-6215`).
Items are sequential; W1.3 and W1.4 share `crl.rs` and are one executor.

| Task | Issue | What lands | Where (on `main` @ `0a90de0`) | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W1.1 | #609 | `CrlDistribution::new` stores `parsed.as_str()` with the trailing slash trimmed, and refuses a URL with userinfo. | `crates/axiam-pki/src/crl.rs:157-176`; callers `boot.rs:1020`, `state/mod.rs:664` | `crl.rs` `mod tests` (~`:517,:528`); `crates/axiam-pki/tests/crl_test.rs:406` (the issued certificate carries the normalised form) | S | Sonnet 5.5 |
| W1.2 | #611(a) | `redirect(Policy::none())` on the four Vault-facing clients; a `3xx` is an error naming the host. New threat entry **T-476** ("a Vault redirect carries `X-Vault-Token` off-host"), Mitigated with the test. | `vault_pki.rs:218`, `ca_key_store.rs:199`, `axiam-server/src/main.rs:151`, `axiam-auth/src/secrets.rs:464`; precedent `boot.rs:1174-1176`, `email/tests/egress_test.rs:378` | wiremock `307` to a second host in `vault_pki_test.rs`, `vault_ca_key_store_test.rs`, `vault_provider_test.rs`: the second host sees nothing | S | Sonnet 5.5 |
| W1.3 | #607 | Per-CA single-flight (a `HashMap<Uuid, Arc<Mutex<…>>>` behind a short global lock, or `DashMap`): a cache hit never waits on another CA's re-sign. The "unchanged" decision reads fingerprints and `revoked_at` only (a light query next to `list_revoked_by_issuer`); PEMs are read only to sign. A bounded wait on the crypto permit, `503` past it. | `crates/axiam-pki/src/crl.rs:259,319-367`; repo `certificate.rs:380-397`; semaphore `boot.rs:688-698` | `axiam-pki/tests/crl_test.rs:331`; `axiam-api-rest/tests/crl_test.rs:167,235`; a new test: CA A's re-sign in flight, CA B's cached list answers | M | Opus 5.5 |
| W1.4 | #608 | CRL number and `thisUpdate` derived deterministically from the newest `revoked_at` and the refresh epoch, so two replicas sign the same state to the same number and `ETag`; `Cache-Control: max-age` cut to the refresh half-life with `ETag` revalidation, never to `nextUpdate`. T-102 and `docs/pki/README.md:1126-1136` say so; contract §35 rule 4 (W5 carries the text). | `crl.rs:62-66,335-343,369`; `handlers/crl.rs:99-109` | two `CrlService`s over one store produce identical bytes; the route's `max-age` ≤ half of `crl_next_update_secs` | M | Opus 5.5 |
| W1.5 | #603 | **v95**: `certificate.vault_forward_attempts`, `vault_forward_last_error`, `vault_next_attempt_at` and an index on `(vault_revoked_at, vault_next_attempt_at)`. The sweep orders by `vault_next_attempt_at`, claims a row by conditionally writing it before the attempt (so two replicas never attempt the same row), backs off exponentially (1 min … 6 h), and reports rows past a threshold as a distinct job-health error instead of failing the pass. | `certificate.rs:400-425,453-479`; `cert.rs:1016-1119,1143-1146`; `cleanup.rs:1263-1270`; `job_health.rs:67` | `vault_pki_test.rs:1462,1487` extended: a permanently refused serial does not block a later one; `certificate_repository_test.rs`; `docs/pki/README.md:457-470` | M | Sonnet 5.5 |
| W1.6 | #612 | **v96**: `ca_certificate.vault_revoked_at`. `CaService::revoke` of a `vault_pki` CA forwards the CA's serial to the **parent's** signing issuer mount (the parent locator's `root` when present, else its issuing mount), before `store.delete`; a failed forward leaves `Pending`, writes `ca_certificate.vault_revocation_pending` (mirroring `handlers/certificates.rs:370-420`), and W1.5's sweep retries from a second query over `ca_certificate`. `docs/pki/README.md:423-434` adds `pki/revoke` on the root mount to the Vault policy; T-470 extended. | `ca.rs:918-993`; `vault_pki.rs:178-186,382-388,518-534,736-791,835-850`; `ca_certificate.rs:335-350`; `handlers/ca_certificates.rs:362`, `handlers/tenants.rs:716` | `vault_pki_test.rs:318` and the `mount_revoke` helper (`:1419`): revoking a tenant CA POSTs the parent mount's `/revoke` with the CA's serial; a refused forward is retried by the sweep | L | Opus 5.5 |
| W1.7 | #610(c) | **v97**: `tenant.purge_claimed_at`. The purge claims a tombstoned tenant with a conditional write (the `claim_reconciliation` pattern) and treats `NotFound` from `purge_tombstoned` as "already purged" (success, no `tenants.purged` row). The Vault sweep's claim is W1.5's. T-472 says one replica purges. | `cleanup.rs:221-291,1306-1322,1383-1408`; `tenant.rs:197-203`; precedent `scim_target.rs:1192-1228` | `cleanup_task.rs:2132` plus a two-task race over one store: one `tenants.purged` row, both sweeps `Ok` | M | Opus 5.5 |
| W1.8 | #533 | **v98**: `certificate.user_id option<string>` and an index. Set by `generate` and `sign_csr` for `User` certificates from a new optional request field, validated against the tenant's users; exposed on the `Certificate` response. `revoke_user_certificates` revokes by `user_id`, falling back to the CN / `metadata.user_id` convention only for rows with `user_id = NONE`. Admin user deletion and the GDPR purge revoke the user's certificates (today neither does). OpenAPI regenerated in-wave; contract text is W5's. T-336 amended; a GDPR-erasure entry gains the certificate line. | `models/certificate.rs:561-587,620`; `cert.rs:346,385,687,897`; `handlers/certificates.rs:29-37,112,162-171,222`; `certificate.rs:481-519`; `directory.rs:617-620`; `users.rs:509ff`; `cleanup.rs:1587,1638`; repository trait `repository.rs:2937-2959` | `directory_provisioning_repo_test.rs:327`: linking revokes by `user_id` and leaves another user's same-CN certificate alone; `certificate_test.rs`; `req14_gdpr_test.rs`; `cleanup_task.rs` | L | Opus 5.5 |
| W1.9 | — | F4 review of the W1 diff → `claude_dev/security-review-release-1.0.1-w1-<date>.md`. Medium and higher fixed in the wave; Low and Informational filed on `1.0.x`. | | | — | Opus 5.5 |

Closes: #603, #607, #608, #609, #612, #533, and the (a) and (c) halves of #611
and #610 (the issues close with the PR once their other halves land).

---

## 3. Wave W2 — SAML and federation (branch `claude/release-1.0.1-w2`)

Builds and tests with the `saml` feature on (`libxml2-dev`,
`libxmlsec1-dev` present); the orchestrator also runs the `build-no-saml`
`cargo check` before each commit, since W2.1 adds a helper under `saml`.

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W2.1 | #605 | `refuse_other_encodings` refuses any document whose first byte is not `<` after ASCII whitespace (so a BOM is refused, not skipped), at the ACS, the metadata parse and the IdP receiver. One `pub(crate) fn receiver_parser_options()` (`no_net`, `no_def_dtd`, `ignore_enc`, `encoding: UTF-8`, `recover: false`) used at `request.rs:389-396`, `sp_metadata.rs:237-244`, `saml.rs:731`, `saml.rs:1022` and `saml_metadata.rs:270`. T-474's correction paragraph (`stride.md:2582`) rewritten: the three sites closed, samael's internal re-parse named as the residual; T-67/T-69 likewise; CHANGELOG known-issues line `:1397` updated. | `saml_idp/request.rs:292-314,382-400`; `saml.rs:415-429,731,1022`; `saml_metadata.rs:128,180,270` | `request/tests.rs:255`, `saml_idp/tests.rs:616`, `saml_metadata.rs:611`: a BOM-prefixed UTF-16-declared document is refused at all three entries | M | Opus 5.5 |
| W2.2 | #606 | With `allow_sha1_signatures = true`, AXIAM reads `SignatureMethod/@Algorithm` and every `Reference/DigestMethod/@Algorithm` from the libxml document it already holds (next to `check_signature_placement`, `saml.rs:736`) and refuses anything outside {the six SHA-2 URIs, `rsa-sha1`, `ecdsa-sha1`, the `sha1` digest}; only then calls samael with `None`. Stale "samael 0.0.19" comment in `axiam-federation/Cargo.toml` corrected. T-67's residual sentence (`stride.md:1741`) rewritten. Contract note 6 wording is W5's. | `saml.rs:752-761`; list `request.rs:97-104` | `saml_idp/tests.rs:564` extended with `resigned_with_sha1` (`:537`): an MD5-based (`rsa-md5`) signature is refused with the flag on, an `rsa-sha1` one verifies, and with the flag off `rsa-sha1` is refused as before | S | Opus 5.5 |
| W2.3 | #611(b) | `federation.idp_signing_cert_changed` / `_cleared` audit rows on `update`, mirroring the metadata-certificate pair; the helper at `:743-776` generalised (the `metadata_signature_checked` field becomes an `Option`). | `handlers/federation.rs:41,46,743-776,1098,1134-1137,1209-1219,1239,1294-1296` | `federation_test.rs:2951` cloned for the assertion certificate | S | Sonnet 5.5 |
| W2.4 | #614 | `build_governor(end_session_per_min)` plus `RateLimitShared::browser_preset("federation_saml_authn_request", …)` on the route. No new `*_per_min` knob, so `rl_prod_check.py` needs no row; its `end_session_per_min` description (`:203-206`) names the bucket. D-3 decides whether the four sibling routes get the same wrap in the same commit. | `server.rs:1816-1830`; preset `rate_limit_shared.rs:191-196`; precedent `server.rs:1976-1981` | a config-taking `test_app` in `federation_test.rs` (as the inline app at `:2731`): `429` past the bucket, another route's bucket untouched (`crl_test.rs:234` shape) | S | Sonnet 5.5 |
| W2.5 | #591 | The four credential-bearing calls use `guarded_fetch_no_redirect`; a `3xx` is `FederationError` naming the endpoint. A source-pin test (as `webhook.rs:426`) and a behaviour test with a wiremock token endpoint answering `307`: the error reason is "redirect not followed" and the second server sees nothing. T-112's rule statement updated; the W6 F4 review's "one exception left" corrected in `claude_dev/security-review-phase23-w6-2026-10-06.md` §15 by a dated note. | `oauth2.rs:334,394,438`; `oidc.rs:769`; guard `ssrf.rs:270-392` | `federation_login_providers_test.rs:918`; `oidc.rs:1489` harness | M | Sonnet 5.5 |
| W2.6 | #538 | The Keycloak round trip gains single logout in both directions on both bindings: (i) Keycloak-initiated — Keycloak's `LogoutRequest` to AXIAM's `/saml/v2/{tenant}/slo`, AXIAM's `LogoutResponse` back, the AXIAM session in `/oauth2/revocations`; (ii) AXIAM-initiated — `/sso/logout` propagating AXIAM's signed `LogoutRequest` to Keycloak's `SingleLogoutService`, Keycloak's `LogoutResponse` consumed, Keycloak's session gone (admin API). `seed()` sets `postBindingLogout`, `singleLogoutServiceUrl` and `backchannelSupported=false`. Wired into the existing CI step (`ci.yml:917-922`), `--test-threads=1`. | `saml_idp_keycloak_roundtrip_test.rs:425-506,671,919,927`; `handlers/saml_idp_slo.rs`; `saml_idp/logout.rs:608,641`; `idp_metadata.rs:301-303`; `sp_metadata.rs:447-475` | the four new `#[ignore]` tests green in the `e2e` job | L | Opus 5.5 |
| W2.7 | — | F4 review of the W2 diff → `claude_dev/security-review-release-1.0.1-w2-<date>.md`. | | | — | Opus 5.5 |

Closes: #605, #606, #614, #591, #538, and the (b) half of #611.

---

## 4. Wave W3 — OAuth2 and tenant lifecycle (branch `claude/release-1.0.1-w3`)

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W3.1 | #604 | After the device code is redeemed and the user re-read, `user_may_be_subject` (CIBA's `account_may_act && !is_locked_out`) gates minting; `invalid_grant` otherwise, nothing minted, the grant consumed. The #520 / P23W1-01 amendment (`stride.md:611-613`) and T-163 name the device grant. | `device_service.rs:328-391`; pattern `token_ciba.rs:194-212`, `ciba.rs:711-713` | `device_flow_test.rs` next to `:447`, modelled on `ciba_test.rs:906`: approve, suspend, poll → `invalid_grant` | S | Sonnet 5.5 |
| W3.2 | #601 | `authenticate_client` reads the tenant once (`get_by_id`, which already filters `deleted_at = NONE`) and maps `NotFound` to `invalid_client`, as `:1220-1231` does for `tls_client_auth`; the read is passed on so a grant does not read it twice. `bc-authorize` checks tenant liveness before storing or mailing (`ciba.rs:113`). T-472 amended. The quick-bench runbook's token cell is re-run once on the orchestrator's box and the number recorded in the commit body (one extra indexed read per call; expected to be within noise). | `token.rs:1220-1231,3184-3222`; callers `token.rs:2926,2975`, `oauth2.rs:4382,4631,5444`, `ciba.rs:136` | `tenant_test.rs:1499` and `tenant_purge_test.rs:129` extended: after the `204`, `client_credentials`, `bc-authorize`, introspection, revocation, PAR, UMA ticket and token exchange answer `invalid_client`, and no mail is sent | M | Sonnet 5.5 |
| W3.3 | #610(d) | `DeviceGrantRepository::delete_all_for_client` and `CibaRequestRepository::delete_all_for_client`; `ClientGrantStores::revoke` calls both. Module doc and the #517 threat entry amended. | `client_grants.rs:46-87`; `repository.rs:1763-1837`; `device_grant.rs`, `ciba_request.rs`; callers `oauth2_clients.rs:1076-1088`, `cleanup.rs:535,562,637` | `oauth2_client_test.rs` and `dynamic_registration_test.rs`: an approved device grant does not redeem after the client is deleted and re-materialised; a pending CIBA request is gone | M | Sonnet 5.5 |
| W3.4 | #613 | Enforcement at the read points, not a rewrite of rows: for a client with `managed_by ∈ {Dcr, Cimd}`, authorize, token mint and refresh intersect `client.scopes` with the tenant's effective `dcr_allowed_scopes` (the merged org/tenant policy), so a withdrawn scope is gone at the next request. Settings handlers untouched. T-289's amendment (`stride.md:1336`) rewritten. Contract behaviour note is W5's. | `token.rs:2596-2625`; `authorize.rs:562`; policy `settings.rs:407,1159,1630-1633`; `dcr.rs:534-539,850`; `cimd.rs:569` | `token_service.rs:2007` and `dynamic_registration_test.rs:1651` extended: withdraw a scope; a refresh for an existing DCR client no longer carries it; a non-DCR client is unaffected | M | Opus 5.5 |
| W3.5 | #602 | The purge deletes `audit_log` rows with `timestamp <= audit_exported_at` only, reading the export time from the `tenants.deleted` system row (`resource_id = tenant_id`; no schema change); later rows stay under the tenant id for the retention sweep, as `PurgeScope::Orphan` already does, and the `tenants.purged` row records how many were kept. `audit_signature` rows whose `entry_ids` are all deleted go with them; others stay. The module doc, T-118, T-472 and `docs/compliance/gdpr-compliance.md` say exactly this. D-5 confirms the route. | `tenant_purge.rs:113-125,255-256,301-305`; `tenant.rs:197,235-262`; receipt `tenants.rs:75,97,127-157,747-748`; `cleanup.rs:264-276` | `tenant_purge_test.rs:254`, `cleanup_task.rs:2132`, `tenant_test.rs:366,583`: a row written after the export survives the purge | M | Opus 5.5 |
| W3.6 | #599 | A per-(client, user) cap on pending requests at `bc-authorize` (3, next to the T-424 throttle; refused with the existing per-client limiter's error shape); the list ordered by `created_at`, client names resolved once per call, and two additive response fields `total_pending` and `truncated`; the `ciba_approval_list` bucket keyed on the signed-in user instead of the IP (D-4). T-424 amended. Contract rule 16 text is W5's. | `handlers/ciba.rs:186-202,244-270`; `ciba.rs:79,771,1183-1211`; `ciba_request.rs:358-383`; `ciba_approval.rs:256-261,283-321`; `rate_limit_shared.rs:161-167`; `usePendingSignInRequests.ts:5` | `ciba_test.rs:973`, `ciba_approval_test.rs:1001-1074`, `ciba_request_repository_test.rs:258`: the fourth pending request of one client for one user is refused; two console users behind one address do not share a bucket | M | Sonnet 5.5 |
| W3.7 | #610(a) | The pro-rating comment corrected in the three test files that carry it. | `tenant_issuer_paths_test.rs:249-260`, `par_test.rs:218`, `oauth2_flow_test.rs:134` | the files compile; no behaviour | S | Sonnet 5.5 |
| W3.8 | #610(b) | A route-level `tls_client_auth` harness: `server_leaf_profile.rs`'s `serve()` gains a client-auth variant so a real TLS client presents a leaf and the `/oauth2/token` route (not the service) is driven. Two tests: a revoked leaf is refused at the route; a leaf of **another tenant's** CA is refused (R1W1-02). | `crl_test.rs:276`; `oauth2.rs:2395-2431`; `boot.rs:3057`, `tls.rs:312,346`; `server_leaf_profile.rs:186` | the two tests green under `cargo test -p axiam-server --test server_leaf_profile` | M | Opus 5.5 |
| W3.9 | — | F4 review of the W3 diff → `claude_dev/security-review-release-1.0.1-w3-<date>.md`. | | | — | Opus 5.5 |

Closes: #601, #602, #604, #613, #599, #610 (with W1.7).

---

## 5. Wave W4 — durability, operations, console and CI (branch `claude/release-1.0.1-w4`)

| Task | Issue | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W4.1 | #597 | No commit. The orchestrator verifies the two sentences and the model status once more, posts one comment naming `6a9047e` and model 2.40.0, and puts #597 on the PR's `Closes` line. | `threat-modeling-and-security.md:3085-3091`; `website/src/security.ts:639`; `stride.md:485,4542` | — | — | Sonnet 5.5 |
| W4.2 | #592 | The "Select the AXIAM image" step validates `AXIAM_IMAGE` against `^[a-z0-9./_-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$` and fails otherwise, before any use; the summary prints "(digest-pinned)" only when the value matched. The runbook's dispatch-input paragraph says so. | `.github/workflows/fapi-conformance.yml:64-69,202-216,323-335` | a `workflow_dispatch` with a tag-only value fails at that step (the orchestrator dispatches it once, or D-7's owner does) | S | Sonnet 5.5 |
| W4.3 | #593 | A second baseline, `conformance/baseline-unattended.json`, recording which modules end `WAITING` on the runner; `gate.py` treats a module that completed unattended before and parks now as a regression; `WAITING` stays tolerated only for modules the unattended baseline lists. The runbook's "green means" paragraph (`:173-180`) says green covers the modules that complete unattended. | `gate.py:40,46,73-97`; `test_gate.py:96`; `conformance/baseline.json`; `claude_dev/fapi-conformance-runbook.md:151-180` | `python3 -m unittest discover -s conformance/scripts -p 'test_*.py'`: the pinned test inverted for a listed module and kept for an unlisted one; recording the baseline needs one unattended run (D-7) | M | Sonnet 5.5 |
| W4.4 | #600 | `toOverride` sends `saml_idp_enabled` / `ssf_enabled` only when the administrator changed the switch or the tenant's own override (`overrideQuery.data`) already carries it; the comment in `services/settings.ts:399-404` rewritten; CHANGELOG lines `:189-190,280-283` superseded by an `[Unreleased]` line. | `frontend/src/pages/settings/SettingsPage.tsx:192-193,228-229,301-305,377` | `SettingsPage.test.tsx:967-1050`: `:1035` keeps passing; a new case: an unrelated save while the organization has the surface off writes no `false` | S | Sonnet 5.5 |
| W4.5 | #590 | `SsfStreamInput.expected_updated_at` (additive, `#[serde(default)]`, utoipa `409` text), checked as `scim_targets.rs:810-820` does, sent by the page from the row it was opened from; the page refuses a save that would empty the receiver's narrowing (an `events_requested` of `[]` is never sent, and an omitted field is never sent for a stream that had a narrowing). OpenAPI regenerated in-wave; contract §32 text is W5's. T-406 wording on the `409`. | `handlers/ssf_admin.rs:163,189-192,722,768`; `SsfStreamsPage.tsx:107-131,475-479`; `services/ssf.ts:134,198`; precedent `scim_targets.rs:220-228,772-775,810-836`, `ScimTargetsPage.tsx:520` | `ssf_test.rs:598,1739,1875` plus the two-`PUT` `409` case; `SsfStreamsPage.test.tsx:196,245` plus "removing every narrowed event does not widen" | M | Sonnet 5.5 |
| W4.6 | #594 | `write_audit_with_dead_letter` appends through `spawn_blocking` (the writer task stays the middleware's); both openers set `mode(0o600)`; `sync_data` after each GDPR record and each writer batch; the env and budget read once at construction. The `dead_letter.rs:14-16,164` doc and `docs/deployment/README.md:1838ff` say "durable, owner-only". T-108 text if it claims either. | `handlers/gdpr.rs:183-210`; `dead_letter.rs:146-192,269-283,358-473` | `gdpr_audit_dlq_test.rs:96,347,361`; `dead_letter_env.rs`; a mode assertion on the created file | M | Sonnet 5.5 |
| W4.7 | #595 | Each line becomes `{"occurred_at","reason","entry"}`; the decoder accepts the bare form too; the README's jq recipe carries `occurred_at` and `dead_lettered_reason` into the replayed row's `metadata`, and the "timestamp is the moment of replay" sentence (`:1960-1962`) says what is now recoverable. Sequential after W4.6 (same file). | `dead_letter.rs:4-5,146-159`; `audit.rs:38-47`; `docs/deployment/README.md:1854-1856,1932,1960-1964` | `gdpr_audit_dlq_test.rs:404` (the recipe test, in lock-step with the README); `request_audit_loss.rs:139` reads both forms | M | Sonnet 5.5 |
| W4.8 | #596 | `AuditMiddleware::try_record(CreateAuditLogEntry)` (non-blocking, the existing 4096-slot channel); `abandon` hands the `delivery_abandoned` row to it instead of awaiting the repository, and the `WARN` is rate-limited on the `NOTIFICATION_DROP_REPORT_INTERVAL` pattern. One row per refusal is kept, so the pinned tests stand. T-445 amended. | `inprocess.rs:97-119,135-161`; `middleware.rs:125,131,146,173-300,344,514` | `inprocess.rs:826,1083,1122,1159`; a new test: with the audit channel full, `publish` returns without a datastore write and the loss counter moves | M | Sonnet 5.5 |
| W4.9 | #598 | `cleanup_handle` joined under a 5 s bound counted in the budget (20 + 5 + 2 + 5 + 5 = 37, margin 3, grace 40; `FATAL_STOP_BACKSTOP` re-derived) and the cleanup tick given a deadline it checks between steps; the lease-loss path runs the orderly stop with a REST timeout that fits its backstop (lease: REST 6 + gRPC 2 + outbound 1 + audit 3 = 12 < 15), as a second `ShutdownBudget` the `const _` asserts cover. T-444 and `docs/deployment/README.md:1705` say which stop can be cut and by how much. | `boot.rs:2766,3132,3172-3189,3238,3262-3270,3296-3341`; `profile.rs:64-73`; `cleanup.rs:1119-1126,1362` | `minimal_profile_boot.rs:779`; `profile.rs:405-471`; a new test: a cleanup tick that sleeps past the bound does not delay the exit past the grace | M | Opus 5.5 |
| W4.10 | — | F4 review of the W4 diff → `claude_dev/security-review-release-1.0.1-w4-<date>.md`. | | | — | Opus 5.5 |

Closes: #590, #592, #593, #594, #595, #596, #597, #598, #600.

---

## 6. Wave W5 — contract 1.61 and the eleven SDK ports (branch `claude/release-1.0.1-w5`, cut from the plan branch after W1, W3 and W4 are merged into it)

Contract 1.61 is **additive and clarifying only**, as 1.60 was. Its record is
**§34.5 "Contract 1.61 — the 1.0.1 fields"**; every rule is marked inline
"(contract 1.61, normative)" or "(…, informative)" in the section it belongs
to. The text is Sonnet 5.5's; the orchestrator reads the contract diff before
the commit.

| Task | Source | Contract change | Where in `sdks/CONTRACT.md` | SDK-visible? |
|---|---|---|---|---|
| W5.1 | W1.8 (#533) | `Certificate.user_id` (optional) and the request field on issue and CSR sign; a §27.11 row as `bound_service_account_id` has (`:8710,8735`); the revocation-by-user rule in §6.1's neighbourhood | §27.5, §27.11 | **yes** — model field in every SDK |
| W5.2 | W4.5 (#590) | `SsfStreamInput.expected_updated_at`, `409` on mismatch; §32.3 rule as §31.3 rule 4 has (`:10830-10831`) | §32.2, §32.3 | **yes** — optional member, as #555's SCIM field (`:12364`) |
| W5.3 | W3.6 (#599) | `CibaPendingList.total_pending`, `.truncated`; ordering by creation; the per-(client, user) cap on `bc-authorize` | §33.3 rule 16 (`:11749-11755`) | **yes** (read-only fields), informative route |
| W5.4 | W2.2 (#606) | note 6 (`:9014-9023`): `allow_sha1_signatures = true` admits SHA-1 **in addition to** SHA-2, nothing else | §29 notes | no |
| W5.5 | W2.3 (#611b) | note 7 (`:9035-9037`): the two new audit action names | §29 notes | no (audit names) |
| W5.6 | W3.4 (#613) | a behaviour sentence: a DCR- or CIMD-managed client's effective scopes are intersected with the tenant's current policy at authorize, mint and refresh | the DCR section | no |
| W5.7 | W1.4 (#608) | §35 rule 4: `max-age` is at most the refresh half-life; `ETag` is deterministic across replicas | §35 | no (informative) |
| W5.8 | W1.6 (#612) | the CA revoke response's pending outcome and audit name, next to the leaf's | §27.5 | no (response unchanged in shape) |
| W5.9 | — | Regenerate `sdks/openapi.json` and `sdks/management-registry.json` (`protoc`, the swagger placeholder, `cargo build -p axiam-server --no-default-features`, `--dump-openapi`, `scripts/check-spec-digest.py`); the drift job green. | | |
| W5.10 | — | Per SDK clone, branch `claude/contract-1.61-sync`: re-vendor `CONTRACT.md`, `openapi.json`, `management-registry.json`, `proto/`; regenerate §27; add the three fields (W5.1–W5.3) with their tests; README conformance statement at 1.61; `## [Unreleased]` → `[1.0.1]`; the SDK's own build and tests; one PR each whose body names the vendored `axiam` commit. Eleven PRs; the seven full-surface SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) and the four REST-only ones (Kotlin, Swift, C, C++) differ only in which transports carry the fields. | | |
| W5.11 | — | `claude_dev/sdk-contract-1.61-conformance-review.md` on the pattern of `sdk-phase23-ports-conformance-review.md` (§1 method, §2 what the suites did not catch, §3 one report per SDK); its findings fixed on the same SDK branches. | | |

Sizes and models: W5.1–W5.8 together **M, Sonnet 5.5** (one session);
W5.9 **S, Sonnet 5.5**; W5.10 **L, Sonnet 5.5** (three or four sessions, three
to four SDKs each; the orchestrator runs them in parallel where the box
allows); W5.11 **M, Sonnet 5.5**. "Every contract error is reported as a
question on the `axiam` PR, never worked around" (1.0.0 plan §4) binds here.

---

## 7. Wave W6 — RADIUS option B (branch `claude/release-1.0.1-w6`; gated by D-2)

The issue says "not scheduled" and names a reopen condition. The maintainer
asked on 2026-10-12 that it be planned with the rest; D-2 records whether that
request is the reopen condition met. If D-2 is "no", W6 is its own `1.0.x`
pull request on the same branch and this plan's PR does not cite #563.

| Task | Spike ref | What lands | Where | Oracle | Size | Model |
|---|---|---|---|---|---|---|
| W6.1 | D5 | `claude_dev/radius-reply-profile-design.md`: the reply-profile data model and the network-segment resource pattern, meeting R17 / T-461 (attribute-type allow-list validated against the dictionary; profile writes behind their own permission and audit row; deny-override for quarantine; a profile cannot grant more than its writer holds). A design note, no code. Opens with the re-read of the eleven recalled RFC claims (spike §9.2), each marked confirmed or corrected with its source. | spike §5.2, §6, §7, §9.2 | the note's checklist against §6; reviewed in W6.3 | S | Opus 5.5 |
| W6.2 | D3 | `docs/pki/freeradius.md` ("802.1X with an AXIAM-issued Device certificate": issue and bind, export the CA, a FreeRADIUS config trusting that CA, TLS 1.3 only, `require_message_authenticator = true`, RadSec where the NAS allows, the CRL refresh interval and its revocation lag); `docker/docker-compose.radius.yml` referencing the upstream FreeRADIUS image and shipping only configuration (GPLv2: nothing of FreeRADIUS is vendored); `.github/workflows/radius-e2e.yml` on the `directory-e2e.yml` pattern (path-filtered, `workflow_dispatch`, gated by `AXIAM_E2E_RADIUS=1`, a missing server is a failure) driving `eapol_test` through issue, bind, accept, wrong CA, and revoked-after-CRL-refresh. Linked from the website's PKI page; the authentik comparison row reads "recipe, not native". The threat entries the recipe's configuration mitigates (T-454 for the supply chain; the NAS-configuration entries the spike's §7 map assigns to R-items the recipe covers) move from Not applicable to Mitigated **with the e2e as their test**; the rest stay Not applicable and say why. | `docs/pki/README.md:1107ff`; `docker/directory/README.md`; `.github/workflows/directory-e2e.yml`; `website/src/docs/`; spike §7 | the five `eapol_test` cases green in the workflow | M | Sonnet 5.5 |
| W6.3 | — | F4 review of the W6 diff (the security wording of the guide against spike §4.2; the threat flips against §6). | | | — | Opus 5.5 |

**D4** (the `rlm_rest` authorize endpoint) is **not in 1.0.1**: the spike
schedules it only once D3 shows the CRL interval or the attribute model
inadequate, and it would need a contract section (1.62) and the §6 bindings as
code. W6.2's guide ends with the paragraph that says so.

---

## 8. Wave W7 — release readiness (on `claude/release-1.0.1`)

| Task | What lands | Model |
|---|---|---|
| W7.1 | Merge W1 … W4 into the plan branch in that order (W1 first, since it owns the schema), then W5 and, if D-2 says so, W6; resolve conflicts; `cargo clean`; the regression gate of the 1.0.0 plan §9.2 in full (every crate's tests, the frontend suite, the conformance tenant-issuer-path tests, Architecture Invariants, `check-doc-links`, `check-spec-digest`, the drift job, the `e2e` job). | Opus 5.5 (orchestrator) |
| W7.2 | The combined F4 review of the plan-branch diff against `main` → `claude_dev/security-review-release-1.0.1-<date>.md`; Medium and higher fixed before the PR. | Opus 5.5 |
| W7.3 | Threat model **2.41.0**: every entry the waves flipped or amended (T-67, T-69, T-102, T-108, T-112, T-118, T-163, T-289, T-336, T-406, T-424, T-444, T-445, T-470, T-472, T-474, the #517 and #520 entries, **T-476**, the W6 flips) consistent across `ThreatDragonModels/Axiam/Axiam.json`, `claude_dev/threat-model-stride.md`, `claude_dev/threat-modeling-and-security.md`, `website/src/threatModel.ts` and `website/src/security.ts`; the open register's counts re-derived. | Sonnet 5.5 |
| W7.4 | `CHANGELOG.md` `## [1.0.1] - <date>` with `Security` and `Fixed` subsections, one line per issue; the eleven SDK changelogs' `[1.0.1]` (W5.10). Version **1.0.1** in every place the 1.0.0 bump touched (`Cargo.toml`, `Cargo.lock`, the pinned crates, the Sidebar string and its test, both k8s image tags, the OpenAPI `info.version` and digest, the management registry, `website/src/version.ts`); the website's news post for 1.0.1 and the security page's deferred-items list (now #513, #561, #563's D4 and whatever W7.2 files). | Sonnet 5.5 |
| W7.5 | The pull request: title `release: 1.0.1`, body listing every wave with its review document, a `Closes` line with the 27 issues (28 with #563 under D-2 "yes"), the eleven SDK PR links, and the hand-off for `scripts/mass-tag.sh --repos all --branch main --tag v1.0.1 --changelog` (dry run first), written for whichever route the maintainer's `main` accepts (1.0.0 plan §10). The agent then subscribes to the PR and drives it to green. | Opus 5.5 (orchestrator) |

---

## 9. The gate before every commit, and the rules that bind every wave

- `CLAUDE.md` in full: signed commits; narrowly scoped cargo commands;
  `cargo clean` between items; the swagger placeholder and `protoc` before any
  server build; `--no-default-features` where libxml2 is absent; exit codes
  from the tool, never a pipeline; no `[lints] workspace = true` on an
  undocumented crate; no new crate without a row in the layering table.
- Per commit, on the touched crates: `cargo fmt -p <crate> -- --check`,
  `cargo clippy -p <crate> --lib --tests -- -D warnings`, the touched test
  binaries (`--test <name>`), and for W2 the `build-no-saml` `cargo check`.
  Console tasks: `npm --prefix frontend run test -- <file>` and the
  type-check. `gate.py` tasks: the `unittest` line in W4.3. Workflow tasks:
  one `workflow_dispatch` where the orchestrator has the means, else D-7.
- Phase 23 plan §7, unchanged: every new route carries a limiter from its
  first commit; every credential-bearing outbound request uses
  `guarded_fetch_no_redirect`; every refusal of a credential check costs one
  verify; every two-writer registry is written conditionally on the version
  read.
- **Schema**: only W1 adds migrations, in the order §2 fixes; each is additive
  (`DEFINE FIELD IF NOT EXISTS`, `DEFINE INDEX IF NOT EXISTS`), with its scope
  test and the newest-version bump. No `UPDATE` backfill (D-6).
- **Contract**: no wave but W5 edits `sdks/CONTRACT.md`; W1.8, W3.6 and W4.5
  regenerate `sdks/openapi.json` in-wave so each wave's drift job is green,
  and W5 regenerates once more after the contract text.
- **Threat model**: nothing enters without the test its mitigation names; a
  correction is recorded as a correction, dated, in the entry's own text.
  Each wave edits the entries its tasks name; W7.3 reconciles the five
  copies once.
- Where this plan and a file disagree, the file wins and the commit body says
  so. An executor that finds a task larger than sized stops at a clean commit
  and reports; the orchestrator re-sizes and re-models by §1.1.

---

## 10. Decisions requested from the maintainer

| # | Decision | Recommendation |
|---|---|---|
| D-1 | **The base commit.** `v1.0.0` is not on `origin` (§0). Do the W1 … W4 branches cut from the tagged `v1.0.0` commit, or from `main` as it stands if the tag is not pushed when W1 starts? | Push the tag first; cut from it. If `main` moves past it before W1, cut from `main` and say so in §11. |
| D-2 | **#563 in 1.0.1.** Does the 2026-10-12 request count as the issue's reopen condition, so that W6 ships in 1.0.1 and the PR closes #563 (D4 still deferred)? | Yes for D3 and D5; #563 stays open with a comment naming D4 as the remaining item, rather than closing. |
| D-3 | **#614's siblings.** Wrap `/federation/saml/acs`, `/federation/saml/metadata`, `/federation/oidc/authorize` and `/federation/oidc/callback` under `api_scope` (`server.rs:1391-1400,1824,1828`) with the same browser-preset bucket family in W2.4? | Yes, in the same commit; the issue's rule ("every route carries a limiter") covers them, and the cost is five lines and one test loop. |
| D-4 | **#599's bucket key.** Key the `ciba_approval_list` bucket on the signed-in user (the route is console sign-in only) rather than the IP? | Yes. |
| D-5 | **#602's route.** Delete only rows at or before the receipt's export time and leave later rows to the retention sweep (no signature rewrite, no schema), rather than copying them into the system log? | Yes; the copy would create unsigned duplicates. |
| D-6 | **#533's backfill.** No `UPDATE` backfill of `user_id` from `metadata.user_id`; the convention fallback covers rows issued before v98, as the issue proposes? | Yes. |
| D-7 | **Runs the agent cannot start.** Recording the unattended conformance baseline (W4.3) and validating the workflow input (W4.2) need a `workflow_dispatch` of `fapi-conformance.yml`; W6.2 needs the `radius-e2e` workflow enabled on the repository. Who dispatches? | The orchestrator, through the GitHub Actions tool where the session has it; else the maintainer, once per item, on the orchestrator's request in §11. |

---

## 11. Wave results (written by the orchestrator as each wave lands)

| Wave | Branch / head | Review document | Closes | Left to the next wave / to 1.0.x |
|---|---|---|---|---|
| W1 | `claude/release-1.0.1-w1` @ `08c4c38` — cut from the tag `v1.0.0` (`0a90de0`), see §11.0 | [`security-review-release-1.0.1-w1-2026-10-13.md`](security-review-release-1.0.1-w1-2026-10-13.md) (`37582a3`): 1 Medium (R101W1-01, fixed in-wave `08c4c38`), 4 Low, 4 Informational | #603, #607, #608, #609, #612, #533; the (a) half of #611 and the (c) half of #610 | Low/Informational filed on `1.0.x`: #615 … #622 (R101W1-02 … -09). To W5: §27.11 `user_id` (W5.1), CRL §35 rule 4 (W5.7), CA-revoke pending outcome and audit names (W5.8). To W7.3: T-472 dated corrections (W1.4, W1.7), T-102, T-470, T-336, T-187, new T-476 |
| W2 | | | | |
| W3 | | | | |
| W4 | `claude/release-1.0.1-w4` @ `a234f32` — cut from the tag `v1.0.0` (§11.0) | [`security-review-release-1.0.1-w4-2026-10-13.md`](security-review-release-1.0.1-w4-2026-10-13.md) (`a3f917c`): 1 Medium (R101W4-01, fixed in-wave `a234f32` with R101W4-06), 5 Low, 5 Informational | #590, #592, #593, #594, #595, #596, #597 (no commit, W4.1), #598, #600 | Low/Informational filed on `1.0.x`: #623 … #631 (R101W4-02 … -05, -07 … -11). To W5: §32 `expected_updated_at` and the `PUT` semantics of `events_requested` (absent = all allowed, `[]` = none; #631: SDK update helpers send what they read); `request_audit.outbound_abandoned_dropped` on `/health/jobs`. To W7: `sdks/openapi.json` is regenerated on W1 and on W4 — the merge conflict is resolved by regenerating. To W7.3: T-406, T-108, T-445, T-444 amendments; R101W4-09's stale stop arithmetic |
| W5 | | | | |
| W6 | | | | |
| W7 | | | | |

### 11.0 Base commit (D-1)

`v1.0.0` was on `origin` when W1 started (2026-10-12; tag object `9b2e6f5` →
`0a90de0`), so W1 … W4 are cut from the tag, as D-1 directs. The plan branch
`claude/release-1.0.1` is cut from `main` at `c6f916e` (the tag plus this plan),
and it carries this section.

### 11.1 W1 — what landed, and where the tree overruled the plan

Ten commits on `v1.0.0`, every one signed. Each item ran as one executor at the
model its row names; none was re-sized.

| Task | Commit | Model | Plan vs tree (from the commit body) |
|---|---|---|---|
| W1.1 #609 | `9637c64` | Sonnet 5.5 | the callers go through `CrlDistribution::resolve`; no caller edit |
| W1.2 #611(a) | `b8f2985` | Sonnet 5.5 | T-476 added (Mitigated; model 476 = 438 / 17 / 21, still 2.40.0). The `main.rs` bootstrap client is reviewed, not tested (R101W1-07, #620) |
| W1.3 #607 | `0df1c7c` | Opus 5.5 | the revocation read already ran outside the lock; the lock covered `load`, the permit wait and the signature. `503` after a 5 s permit wait |
| W1.4 #608 | `fe77681` | Opus 5.5 | **not in the row:** the tenant purge keeps revoked certificate rows until `notAfter` + 8 days (a list keeps an expired entry at most one interval, ≤ 7 days by `boot.rs`'s bound); the four revocation reads take the cut-off from the caller. T-472 correction |
| W1.5 #603 | `f05bd40` | Sonnet 5.5 | v95. The due read is a second method; the "distinct job-health error" is a second job, `vault_revocation_failing`, so `JobStatus` (an OpenAPI schema) is unchanged |
| W1.6 #612 | `363b40d` | Opus 5.5 | v96 also carries the three backoff columns on `ca_certificate`. **The forward runs after `store.delete`, not before:** Vault refuses `/revoke` of a serial that is still an issuer in the same mount (confirmed by the F4 review; residual R101W1-04, #617) |
| W1.7 #610(c) | `5844249` | Opus 5.5 | v97. `purge_tombstoned`'s final delete now counts what it removed so that `NotFound` means "already purged"; lease 1 h |
| W1.8 #533 | `2b6607a` | Opus 5.5 | v98; no backfill (D-6). `sdks/openapi.json` and `sdks/management-registry.json` regenerated (they also carry W1.3/W1.4/W1.6's route text). The name fallback applies to every `user_id = NONE` row |
| W1.9 | `37582a3` | Opus 5.5 | the F4 review; one Medium |
| R101W1-01 | `08c4c38` | Opus 5.5 | revoke-by-name skips certificates older than the account and names another account of the tenant shares; checked inside the query, not through `identity_collision`. Linking no longer revokes an unbound certificate whose name a case-variant sibling also holds (deliberate; revocable by id) |

Residual recorded, not fixed: an erased account's revoked certificate rows keep
the PEM, subject and `metadata` for the tenant's lifetime (T-187; R101W1-05,
#618).

### 11.4 W4 — what landed, and where the tree overruled the plan

Twelve commits on `v1.0.0`, every one signed; no item was re-sized.

| Task | Commit | Model | Plan vs tree / note |
|---|---|---|---|
| W4.1 #597 | — | orchestrator | the tree verified again; comment issuecomment-6131477654; on the `Closes` line |
| W4.2 #592 | `4156b80` | Sonnet 5.5 | the report step's `env:` block removed rather than edited. D-7: run 38300274398 (tag-only image) failed at "Select the AXIAM image", later steps skipped — the oracle holds |
| W4.3 #593 | `ba562d8`, `b34a0d0` | Sonnet 5.5 | first commit seeded `baseline-unattended.json` from the tree; the second records it from run 38317560409 (`module_timeout` 30; run 38300842144 at the default 180 s hit the job's 150-minute cap), transcribed from the gate log because the session cannot fetch artifacts (R101W4-10, #630). The seed's one error (`…nbf-8-seconds-in-the-future-is-accepted` parks: a success path) is corrected. Confirmation run 38327426158: **green** |
| W4.4 #600 | `31ca687` | Sonnet 5.5 | two existing assertions pinned the always-send and changed. Turning a surface on under an organization `false` now saves silently (R101W4-07, #627) |
| W4.5 #590 | `11de0b3` | Sonnet 5.5 | **accepted deviation:** the page sends `[]` only when the receiver's stored narrowing already is `[]` (sending it back does not widen; refusing would block pausing such a stream). OpenAPI regenerated |
| W4.6 #594 | `7bbdfa5` | Sonnet 5.5 | the interleave sub-item dropped, as §0.1 said (one `write_all` per record, now pinned by a test); an existing 0644 file is tightened to 0600 at open |
| W4.7 #595 | `94c2747` | Sonnet 5.5 | `crates/axiam-audit/src/loss.rs` and `axiam-server/src/job_health.rs` changed for the new signatures |
| W4.8 #596 | `82e580e` | Sonnet 5.5 | only the producer's refusal goes through the non-blocking path; the consumer's stop paths still await. Introduced R101W4-01 |
| W4.9 #598 | `334943a` | Opus 5.5 | **the lease-loss REST cut is 5 s, not 6:** the cleanup join (2 s) is on that path too, 5 + 2 + 1 + 3 + 2 = 13 < 15; `ORDERLY_STOP` 37, backstop 38, grace 40. The REST cut drops the actix `Server` (actix reads one stop command only). A cut can leave an erasure without its audit row (R101W4-03, #624) |
| W4.10 | `a3f917c` | Opus 5.5 | the F4 review (a first attempt was lost to a container restart before it committed anything) |
| R101W4-01 | `a234f32` | Opus 5.5 | bulk SCIM producers stop at the first refusal and the publisher writes one summary row (`OutboundPublisher::record_not_offered`, since `axiam-scim` has no audit sink) — so a run meeting a full queue leaves at most two rows; `try_record` keeps a quarter of the audit channel for request rows and counts what it sheds in `request_audit.outbound_abandoned_dropped` (closes R101W4-06). OpenAPI regenerated |

---

## 12. Kickoff prompts

### Orchestrator

> Read `CLAUDE.md`, `claude_dev/release-1.0.1-plan.md` in full and the four
> 1.0.0 review documents its issues cite
> (`claude_dev/security-review-release-1.0.0-w1-2026-10-10.md`,
> `…-w2-2026-10-10.md`, `claude_dev/security-review-phase23-w3-2026-10-04.md`
> §P23W3-10, `…-w4-2026-10-04.md` §14). Confirm D-1 … D-7 are answered in §10;
> ask for any that is not before W1. Run W1 … W4 as independent branches from
> the base D-1 names, each item by one executor at the model its row names,
> each wave ending with its F4 review; then W5 on the merged plan branch; W6
> under D-2; then W7. Record every wave in §11 as it lands. Re-size and
> re-model by §1.1 whenever an executor stops short, and say so in §11.

### W1

> Read `CLAUDE.md`, `claude_dev/release-1.0.1-plan.md` §0–§2 and §9, and
> `claude_dev/security-review-release-1.0.0-w1-2026-10-10.md` §4, §8, §9 and
> §12. Check out `claude/release-1.0.1-w1` from the base D-1 names. Execute
> W1.1 … W1.8 in order, one signed commit per item (two where the threat-model
> flip is its own commit), each with the tests its row names, its migration
> (v95 … v98, in that order) with the scope test and the newest-version bump,
> and its threat-model entry in the same commit; run the §9 gate before each
> commit and `cargo clean` between items. End with the F4 review of the wave
> diff in `claude_dev/security-review-release-1.0.1-w1-<date>.md`; fix Medium
> and higher in the wave, file Low and Informational on `1.0.x`. Record the
> head in §11.

### W2

> Read `CLAUDE.md`, the plan §0–§1, §3 and §9, and the 1.0.0 W1 review §8 and
> §11 and the W2 review §4. Check out `claude/release-1.0.1-w2` from the base.
> Install `libxml2-dev` and `libxmlsec1-dev`; run the `build-no-saml`
> `cargo check` before every commit as well as the gate. Execute W2.1 … W2.6 in
> order; W2.6 needs the `e2e` compose stack (`docker/docker-compose.e2e.yml`)
> and `KEYCLOAK_URL=http://localhost:8180`. End with the F4 review in
> `claude_dev/security-review-release-1.0.1-w2-<date>.md`; record the head in
> §11.

### W3

> Read `CLAUDE.md`, the plan §0–§1, §4 and §9, and the 1.0.0 W1 review §6, §9
> and §10 and the W2 review §7. Check out `claude/release-1.0.1-w3` from the
> base. Execute W3.1 … W3.8 in order; W3.2 records its quick-bench number in
> the commit body; W3.5 follows D-5, W3.6 follows D-4. No schema change in this
> wave (if a task seems to need one, stop and report). End with the F4 review
> in `claude_dev/security-review-release-1.0.1-w3-<date>.md`; record the head
> in §11.

### W4

> Read `CLAUDE.md`, the plan §0–§1, §5 and §9, and the 1.0.0 W2 review §6, §7,
> §8 and §10. Check out `claude/release-1.0.1-w4` from the base. W4.1 is a
> comment and a `Closes` entry, no commit. Execute W4.2 … W4.9 in order (W4.7
> after W4.6, same file); console tasks run the frontend suite and type-check,
> `gate.py` tasks the `unittest` line, workflow tasks one dispatch under D-7.
> End with the F4 review in `claude_dev/security-review-release-1.0.1-w4-<date>.md`;
> record the head in §11.

### W5

> Read `CLAUDE.md`, the plan §6 and §9, `sdks/CONTRACT.md` §34.4 and §35, and
> the 1.0.0 plan §4. Check out `claude/release-1.0.1-w5` from the plan branch
> with W1, W3 and W4 merged. Write contract 1.61 (§34.5, inline markers,
> additive only), regenerate the spec and the registry, commit. Then, per SDK
> clone, branch `claude/contract-1.61-sync`, re-vendor, regenerate §27, add
> the three fields with tests, README at 1.61, `## [Unreleased]` → `[1.0.1]`,
> the SDK's own build and tests, one PR naming the vendored `axiam` commit.
> Write the conformance review and fix what it finds on the same branches.
> Every contract error is a question on the `axiam` PR, never worked around.

### W6 (only under D-2)

> Read `CLAUDE.md`, the plan §7 and §9, and
> `claude_dev/radius-eap-tls-spike-2026-10-06.md` §4.2, §5.2, §6, §7, §8 and
> §9.2. Check out `claude/release-1.0.1-w6` from the plan branch. W6.1 first:
> re-read the eleven recalled claims against their sources before writing a
> line of the design note. Then W6.2 on the `directory-e2e.yml` pattern;
> nothing of FreeRADIUS is vendored. End with the F4 review; record the head in
> §11.

### W7

> Read `CLAUDE.md`, the plan §8–§11 and the 1.0.0 plan §9.2 and §10. On
> `claude/release-1.0.1`, merge the waves in §8's order, run the regression
> gate in full, write the combined F4 review and fix Medium and higher, bring
> the threat model to 2.41.0 across its five copies, write `[1.0.1]` and bump
> the version everywhere the 1.0.0 bump touched, open the pull request with
> its `Closes` line and the hand-off for `mass-tag.sh`, subscribe to it and
> drive it to green.
