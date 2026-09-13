# Plan — first-login MFA enrolment residuals, and end-entity certificates from a CSR

> **Status: PLANNED — reviewed 2026-09-13 against `main` at `9a5ba6a`
> (1.0.0-beta14, contract 1.44, threat model 2.14.0). Not started.**
> Each section below is sized to be one executable task. When a task lands,
> prepend an `EXECUTED` block to its section in the form
> [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) uses:
> what shipped, which tests went in, what the plan did not anticipate.

Two features were reported as apparently missing on the admin UI side:

1. Under a tenant or organization that **requires MFA**, a user with no
   factor — a newly created one in particular — must be able to enrol during
   the first login, must enrol at least one factor to get in, and must not be
   re-prompted afterwards unless an administrator resets the account.
2. In **Certificates**, a certificate can be generated under a signing CA
   with a server-made key; it must also be possible to **upload a CSR** and
   obtain a certificate for a key AXIAM never sees.

The code review says: **feature 1 exists end to end and works as specified,
with four residuals** — two of them security-relevant; **feature 2 exists only
for tenant signing CAs**, and the end-entity half is genuinely missing on every
layer (server, contract, SDKs, admin UI). This plan works the residuals of the
first and builds the second.

| Item | Layer | What | Model |
|---|---|---|---|
| M-1 | server | Admin MFA reset also evicts WebAuthn credentials | Sonnet 5 |
| M-2 | server + UI | Self-service MFA reset refused where policy enforces MFA | Sonnet 5 |
| M-3 | server + UI + contract + SDKs | Passkey or security key as the first factor at forced setup | **Opus 5** |
| M-4 | UI | Forced setup carries the OAuth2 login-hop `return_to` | Sonnet 5 |
| M-5 | server | Setup token single-use (optional hardening) | Sonnet 5 |
| C-1 | server + spec | `POST /api/v1/certificates/sign-csr` | **Opus 5** |
| C-2 | UI | "Sign a CSR" on the Certificates page, paste or upload | Sonnet 5 |
| C-3 | docs + contract + threat model | Contract 1.45, PKI guide, website, model 2.15.0 | Sonnet 5 |
| F-1 | 11 SDK repositories | One fan-out wave for M-3 and C-1 together | Sonnet 5 |

The model column is the recommendation for the executing agent: Opus 5 for
the two tasks that touch credential issuance or session issuance and have a
design surface (M-3, C-1); Sonnet 5 for everything that is a mechanical
mirror of code that already exists next to it.

---

## 1. Review findings

### 1.1 Feature 1 — forced MFA enrolment at first login

**Exists, and matches roadmap T14.1 / design §8c.1 in every respect but one.**

| Piece | Where | State |
|---|---|---|
| Policy | `crates/axiam-core/src/models/settings.rs:36-39` `MfaPolicy { mfa_enforced, mfa_challenge_lifetime_secs }`; org setting with tenant override; a tenant may not switch off what the org enforces (`clamp_enable_only!`, `:789`) | in place |
| Login branch | `crates/axiam-auth/src/service.rs:419-455` `complete_authenticated_login`: policy enforces **and** `!user.mfa_enabled` → `LoginResult::MfaSetupRequired { setup_token }`; the setup token is an EdDSA JWT, `purpose: "mfa_setup"`, TTL `mfa_challenge_lifetime_secs` (default 300 s) | in place |
| Wire | `POST /api/v1/auth/login` → `403 { "mfa_setup_required": true, "setup_token" }` (`handlers/auth.rs:214-218`); identical branch on OPAQUE `login/finish` (`handlers/opaque.rs:359-360`) | in place |
| Enrolment with the setup token | `POST /api/v1/auth/mfa/setup/enroll` and `/setup/confirm` (`handlers/auth.rs:912-965`); `confirm` completes the interrupted login with cookies and AMR `[pwd, otp, mfa]` (`service.rs:1246-1271`); test `mfa_setup_full_flow_sets_cookies` | in place |
| No re-prompt | the gate is `mfa_enabled`, which `confirm` flips on; a user with one factor is challenged, never re-enrolled; `setup/enroll` refuses an account that already has a factor (`MfaAlreadyConfigured`) | in place |
| Admin unlock | `POST /api/v1/users/{id}/reset-mfa` (`handlers/auth.rs:1187-1204`), self **or** `users:admin`; `UserDetailPage.tsx:417-421` "Reset MFA" with confirm dialog | in place |
| Admin UI | `LoginPage.tsx:590-592` routes the `403` to the public `/auth/mfa-setup?setup_token=…` (`MfaSetupPage.tsx`, outside the auth guard, refresh-safe — CQ-F31 / D-16) | in place |
| Contract | §25.2 rule 1: `login` has three outcomes; every one of the eleven SDKs models `mfa_setup_required` (contract 1.28) | in place |
| Federated users | exempt from the policy-driven setup, by design (T14.1: "not applicable for federated/social login") | in place |

**Residuals found by the review:**

- **R-A (security, M-1).** `AuthService::reset_mfa` (`service.rs:1275-1293`) sets
  `mfa_enabled = false`, clears the TOTP secret and revokes sessions — and
  **leaves every WebAuthn credential in place**. The `WebauthnCredentialRepository`
  trait has no per-user delete at all (`repository.rs:2784-2815`). The admin UI
  says the reset "removes ALL MFA methods" (`UserDetailPage.tsx:517`); it does not.
  Consequence: an administrator who resets a user because a passkey is suspected
  compromised has not evicted it. At the next login the user is forced through
  TOTP setup (the gate is `mfa_enabled`), `confirm` flips the flag back on, and
  `available_method_types` (`axiam-auth/src/mfa_methods.rs:77-104`) lists
  `webauthn` again because the credential count is still non-zero. The stale
  authenticator is a valid second factor once more, without anyone having
  re-registered it. This is the residual of T-34 ("Admin MFA reset abused as a
  takeover path"), which the model records as Mitigated.
- **R-B (security, M-2).** The same endpoint is **self-service**: a signed-in
  user can reset their own MFA with no fresh authentication, no password, no
  policy check (`handlers/auth.rs:1194-1197`; compare `password/change`, which
  re-verifies the current password against exactly this pivot, T-04-21).
  Under `mfa_enforced` this is the one path by which a user takes their own
  account below the tenant's floor: sessions are revoked, but the next password
  login hands out a setup token and whoever holds the password enrols a factor
  of their choosing. It also contradicts the requirement as stated — "it won't
  be re-prompted without an admin intervention". The per-method delete already
  refuses the last factor (`MfaCannotRemoveLastMethod`); the reset does not.
- **R-C (functional gap, M-3).** The forced-setup page offers **TOTP only**.
  `POST /auth/webauthn/register/start` and `/finish` take the full-session
  extractor (`handlers/webauthn.rs:252, :391`) and there is no setup-token
  variant; contract §24.1 says as much. Roadmap T14.1 and design §8c.1 both say
  "choose TOTP, passkey, or hardware key". A tenant whose authenticator policy
  is built around security keys still has to hand every new user a TOTP app for
  their first login.
- **R-D (functional gap, M-4).** `LoginPage.tsx:303-319` resumes the OAuth2
  authorization request named by a sanitized `return_to` after a successful
  sign-in; the setup branch at `:590-592` drops it, and `MfaSetupPage.tsx:90`
  always lands on `/dashboard`. A new user of an enforcing tenant who arrives
  through a `browser_sso` client's `/oauth2/authorize` hop completes enrolment
  and is left in the admin UI instead of back in the application.
- **R-E (hardening, M-5, optional).** The setup token is stateless: nothing
  records that it was spent. Within its 300 s window a captured token lets a
  second party call `setup/enroll` — which **replaces** the pending secret —
  and then `confirm`, completing the login as the user. The window is short,
  the token travels only under TLS, and after the legitimate `confirm` the
  token is inert (`enroll` refuses a configured account, `confirm` needs the
  stored secret), so this is low; it is recorded because
  `MfaSetupPage.tsx:44-47` describes the token as single-use and it is not.

### 1.2 Feature 2 — a certificate from an uploaded CSR

**Exists for tenant signing CAs; missing for end-entity certificates.**

| Piece | Where | State |
|---|---|---|
| CSR → intermediate CA | `POST /organizations/{org}/tenants/{tenant}/signing-cas/sign-csr` → `CaService::sign_intermediate_csr` (`axiam-pki/src/ca.rs:528-663`): `CertificateSigningRequestParams::from_pem` verifies the self-signature (proof of possession), the CSR's subject is kept, its requested extensions are **discarded** and AXIAM states CA:TRUE / pathlen 0 / keyCertSign itself; row custody `External` (T-194) | in place |
| Admin UI for it | `SigningCaPanel.tsx:448-491` "Sign a CSR" — paste-only textarea, no file input | in place |
| Contract / SDKs | `ca_certificates.sign_signing_ca_csr` in `management-registry.json`, generated into all eleven SDKs | in place |
| CSR → **leaf** | **none.** `POST /api/v1/certificates` (`CertService::generate`, `cert.rs:110-290`) always generates the key and returns it once; `CreateCertificate` has no `csr_pem`; `CertificatesPage.tsx` has no CSR control; `certificates` namespace has four operations (`list`, `generate`, `get`, `revoke`) | **missing** |

Two facts about the existing leaf path shape the design below:

- Leaves carry **no SAN, no key usage, no EKU** (`cert.rs:246-259`: CN only,
  `IsCa::NoCa`, validity). A CSR-signed leaf must come out the same shape, or
  the two paths issue different certificates for the same request.
- Under `vault_pki` custody, leaves are signed by Vault's **`sign-verbatim`**
  (`vault_pki.rs:630-651`), which takes the CSR's subject *and SANs* as given.
  That is fine while AXIAM builds the CSR (`generate_remotely`, `cert.rs:297`);
  it is not fine for a CSR a caller built, unless AXIAM has already refused
  anything verbatim would honour. Hence rule 3 in §4.1.

---

## 2. Security assessment of the two features

**Neither feature opens a hole when built as specified below; both close
one.** The review found the holes R-A and R-B *in the existing code*, and this
plan fixes them before touching anything else. The properties that must hold
after the plan, each with the threat it belongs to:

| Property | Threat | Held by |
|---|---|---|
| A factor removed by an administrator is gone — every kind of factor | T-34 | M-1 |
| A tenant floor of "MFA on" cannot be lowered by the user it binds | T-34, new T-267 | M-2 |
| The setup token authorises enrolment on an account **with no factor**, and nothing else; it cannot add a factor to an account that has one | T-32, T-201 | already true for TOTP; M-3 keeps it for WebAuthn |
| A passkey enrolled at forced setup obeys the tenant's attestation and user-verification policies exactly as one enrolled from the profile page | T-229, T-230 | M-3 |
| A CSR is signed only if the requester proves possession of the key | new T-268 (leaf twin of T-194) | C-1 rule 1 |
| A CSR's requested extensions never reach the certificate; AXIAM decides that it is a leaf | T-194, T-268 | C-1 rule 3 |
| A CSR with a weak key is refused, not recorded as `Rsa4096` | T-96 | C-1 rule 2 |
| A CSR-signed leaf is tenant-scoped exactly as a generated one | T-98 | C-1 rule 4 |
| No private key crosses the wire in either direction on the CSR path | T-99, T-105 | by construction — the response type has no key field |

---

## 3. Decisions taken — read before starting, override here if you disagree

These were taken so the plan could be written without a round trip. Each is
the conservative reading; none is expensive to flip before work starts.

- **D-1 — Self-service reset is refused under an enforcing policy, and stays
  allowed otherwise.** `POST /users/{own id}/reset-mfa` answers `403` with
  error code `mfa_enforced` when the caller's tenant's effective
  `mfa_enforced` is true; `users:admin` is unaffected. Under a non-enforcing
  tenant the user may still reset their own MFA (they were free to run at one
  factor anyway). Contract §5.2's self-service row gains one sentence.
  *Alternative considered:* requiring a fresh authentication or the current
  password for every self-service reset. Rejected for this plan because
  OPAQUE tenants have no password AXIAM can re-verify, and a "recent MFA"
  requirement is the `max_age` machinery — a separate piece of work. Recorded
  as a follow-up in §8.
- **D-2 — Forced setup offers every factor the tenant allows: TOTP, platform
  passkey, security key.** Not TOTP-only with a link to enrol a passkey later,
  because that link would be the profile page, which needs a session the user
  cannot get. The chooser respects `isWebauthnSupported()` and the tenant's
  attestation policy (a policy that excludes synced passkeys hides that
  option, per `docs/admin/authenticator-policies.md`).
- **D-3 — A leaf CSR carrying a `subjectAltName` request is refused (400),
  not silently stripped.** Silent stripping is what the intermediate path does
  for its extensions, but there the caller cannot have meant them (a CA has no
  SANs). A caller who put SANs in a leaf CSR meant them; issuing a certificate
  without them and saying nothing produces a credential that fails where it is
  deployed. Refusing with a message that names the rule is honest, keeps the
  DB path and the Vault `sign-verbatim` path byte-equivalent in what they
  honour, and leaves SAN support as a clean follow-up (§8) rather than a
  half-behaviour.
- **D-4 — Accepted CSR keys are exactly the `KeyAlgorithm` set: Ed25519, and
  RSA with a modulus of ≥ 4096 bits.** ECDSA P-256/P-384 are refused with a
  message naming the two accepted algorithms. Note `parse_ca_certificate`
  (`ca.rs:1107-1121`) maps *any* RSA OID to `Rsa4096`; the modulus check must
  be explicit or an RSA-2048 CSR would be signed and recorded as 4096.
- **D-5 — Parity over improvement: CSR-signed leaves get the same extension
  set as generated leaves (none).** Adding KU/EKU to one path only would be a
  worse outcome than the status quo. Giving both paths a per-`cert_type`
  KU/EKU profile is a follow-up (§8) that should be decided once, for both.
- **D-6 — Permission is `certificates:generate`, not a new one.** Precedent:
  `signing-cas/sign-csr` reuses `ca_certificates:generate`. A caller allowed to
  mint a certificate under a CA is allowed to mint one for a key they hold;
  the CSR path is strictly less powerful (no key leaves the server).
- **D-7 — One contract version (1.45) and one SDK fan-out wave** covering M-3
  and C-1 together, at the end. Two waves through eleven repositories for two
  additive changes is the expensive way to do this.

---

## 4. Server-side work

Every `axiam` commit: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings` (or the narrow
per-crate forms `CLAUDE.md` prescribes, with `cargo clean` between items),
`scripts/check-crate-layering.py`, `scripts/check-doc-links.sh`, a
`CHANGELOG.md` entry under `[Unreleased]`, and the threat-model bookkeeping
of §7 **in the same commit as the fix it describes**. `SWAGGER_UI_DOWNLOAD_URL`
per `CLAUDE.md` after any `target/` wipe.

### M-1 — `reset_mfa` evicts WebAuthn credentials (Sonnet 5)

**Closes** R-A. **Threat:** T-34's mitigation text gains the sentence.

1. `axiam-core/src/repository.rs` — `WebauthnCredentialRepository::delete_by_user(tenant_id, user_id) -> u64`.
   `axiam-db/src/repository/webauthn_credential.rs` (or wherever the impl
   lives — find it by the trait name) — implement; repository test in
   `axiam-db/tests/`.
2. `axiam-auth/src/service.rs` `reset_mfa` — call it before
   `invalidate_user_sessions`. `AuthService` may not hold the credential
   repository today; if it does not, the smallest honest change is to move the
   reset into `MfaMethodService` (`axiam-auth/src/mfa_methods.rs`), which
   already holds both repositories and already owns "the last method goes".
   Keep the handler's call site the only thing that changes in `axiam-api-rest`.
3. Tests: `axiam-api-rest/tests/auth_test.rs` (or `mfa_methods_test.rs`) —
   `reset_mfa_removes_passkeys_as_well_as_totp`: register a WebAuthn
   credential (the existing WebAuthn test helpers build one), reset, assert
   `GET /users/{id}/mfa-methods` is empty and the next login answers
   `mfa_setup_required` rather than a `webauthn` challenge. Also
   `reset_mfa_then_totp_setup_does_not_resurrect_the_old_passkey` — the
   scenario in R-A, end to end.
4. `CHANGELOG.md` under **Security**. Website: the reset copy in
   `website/src/docs/authentication.ts` if it describes the reset; otherwise none.

### M-2 — self-service reset refused where MFA is enforced (Sonnet 5)

**Closes** R-B. **Decision** D-1. **Threat:** new **T-267** (§7).

1. `handlers/auth.rs::reset_mfa` — in the `is_own_resource` branch, read the
   caller's *own* tenant's effective settings (`settings_repo.get_effective_settings(org_id, principal_tenant_id)` — the same
   tenant rule `start_registration` uses and explains at
   `handlers/webauthn.rs:258-264`) and refuse with `AxiamError` → `403`
   `{ "error": "mfa_enforced", … }` when `mfa.mfa_enforced`. Add the variant to
   `axiam-api-rest/src/error.rs` beside `opaque_required` (`:86`). The
   `users:admin` branch is untouched.
2. OpenAPI: add the `403` to the `reset_mfa` annotation with the code named.
3. Frontend: wherever the profile UI offers a self-reset (check
   `MfaManagementPage.tsx` and `ProfilePage.tsx`; the review found per-method
   delete there, and a reset only on the admin `UserDetailPage`), hide it when
   `mfa_enforced` is true in the effective settings the page already has or
   can fetch, and map the `403 mfa_enforced` to a sentence that names the
   administrator rather than "forbidden". If no self-reset control exists in
   the profile UI, note that in the EXECUTED block and change nothing.
4. Tests: `self_reset_is_refused_under_an_enforcing_tenant` (403, code
   `mfa_enforced`, factors untouched), `self_reset_still_works_where_mfa_is_optional`,
   `admin_reset_ignores_the_enforcement_flag`. Frontend test for the hidden
   control if one existed.
5. Contract §5.2 (the self-service row that lists `POST /users/{own id}/reset-mfa`,
   `CONTRACT.md:492`): one sentence — "refused with `403 mfa_enforced` where
   the caller's tenant enforces MFA; an administrator resets it". This is
   contract text and rides the 1.45 bump of C-3; write it now, version it there.

### M-3 — a passkey or security key as the first factor (Opus 5)

**Closes** R-C. **Decision** D-2. **Threats:** T-201 and T-229/T-230 texts gain
a sentence; new **T-269** (§7).

**Server.** Two endpoints under the `webauthn_per_min` buckets in
`server.rs`, registered next to `/webauthn/register/*` and shaped exactly like
the TOTP twins `/mfa/setup/enroll` and `/mfa/setup/confirm`:

| Wire | Auth | Request | Success |
|---|---|---|---|
| `POST /api/v1/auth/webauthn/setup/register/start` | none — `setup_token` in body | `{ setup_token }` | `200 StartRegistrationResponse` |
| `POST /api/v1/auth/webauthn/setup/register/finish` | none — `setup_token` in body | `{ setup_token, state_token, credential_name, response }` | `200 LoginSuccessResponse` + cookies |

Rules, each of which is a test:

1. Both decode the token with `AuthService::decode_mfa_setup_token`
   (`service.rs:1492-1533`); a `mfa_challenge`-purpose token, an expired one,
   or a session bearer are all `401` — the token is the only credential, as
   §25.2 says for TOTP.
2. `start` refuses an account that already has a factor with the same
   `MfaAlreadyConfigured` answer `setup/enroll` gives (`service.rs:1226-1239`) —
   the setup token adds a first factor, never a second.
3. `start` reads the attestation policy and the user-verification policy from
   the token's `tenant_id` — which for a setup token *is* the principal
   tenant — and calls `start_registration_for_policy` with them; `finish` runs
   `enforce_mds_freshness` and `finish_registration_for_policy` unchanged.
   Nothing about *what may register* differs from the profile-page ceremony.
4. `finish` persists the credential, calls `enable_after_enrollment` (as
   `finish_registration` does at `webauthn.rs:439`, but here a failure **is**
   the request's failure — there is no profile page to catch it later), and
   completes the login the way `confirm_mfa_with_setup_token` does
   (`service.rs:1246-1271`), with the evidence the WebAuthn *authentication*
   path records for the same credential kind (`Amr::Hwk`/`Amr::Swk`, `Amr::User`
   when user verification happened, `Amr::Mfa`, plus `Amr::Pwd` for the
   password that earned the setup token). Read `acr.rs:128-142` first: the ACR
   class the session ends up in must be `urn:axiam:acr:mfa`, and the test
   asserts it through `/oauth2/authorize`'s honour lane, not by inspecting the
   session row.
5. Factor this so the TOTP and WebAuthn completions share one
   "complete a setup-token login" function in `AuthService` rather than two
   copies of the session-issuance tail; `basic-op-gap-plan.md` §4 lists the
   session-issuance choke points and this must not add an unlisted one.
6. A federated user (one with a federation link) never receives a setup
   token; nothing changes there.

OpenAPI annotations with tag `webauthn`; `--dump-openapi` →
`sdks/openapi.json`; `scripts/check-spec-digest.py --write`;
`scripts/gen-management-registry.py` (the `webauthn` tag is excluded from
§27, so the registry's `excluded_tags` note is the only thing to re-read —
the count does not move).

**Admin UI.** `MfaSetupPage.tsx` grows a method chooser above the current
`TotpSetupPanel`: *Authenticator app* / *Passkey on this device* /
*Security key*, the last two shown only when `isWebauthnSupported()` and
mirroring the affordances and error classification `MfaManagementPage.tsx`
already uses for the same two kinds (`webauthnService.register`,
`classifyWebauthnError`). `services/webauthn.ts` gains
`registerWithSetupToken(setupToken, name, kind)` beside `register`, calling
the two new routes and returning the `LoginSuccessResponse` so the page can
run the same `fetchCurrentUser()` tail the TOTP branch runs. The
`enrolledRef` once-guard stays for the TOTP branch (it is what protects the
single-`enroll` call), and the WebAuthn branch is started by a click, so it
needs none. Tests in `MfaSetupPage.test.tsx` for the chooser, the
unsupported-browser fallback, a completed passkey enrolment landing signed
in, and a policy `403` rendered as the policy message rather than "invalid
link". `frontend/e2e/mfa-setup.spec.ts` gets the chooser assertion (the
ceremony itself is mocked there today, and stays mocked).

**Contract** (text now, versioned in C-3): §24.1's table gains the two
operations with auth "none (setup token)"; §24.0's division of labour is
unchanged (the SDK still only moves JSON); §24.7's per-language naming map
gains `webauthn_setup_register_start` / `webauthn_setup_register_finish`;
§24.8 gains the test "a `setup/register/finish` adopts credentials exactly as
`mfa_setup_confirm` does (§25.2 rule 2)"; §25.1 gains the two rows and §25.2
rule 2 says "either completion". §25.3's `Sensitive<T>` table already covers
`setup_token` and `state_token` is not a secret (it is already unwrapped in
§24.5 — check and keep it consistent).

### M-4 — forced setup keeps the login-hop `return_to` (Sonnet 5)

**Closes** R-D. No server change.

1. `LoginPage.tsx:590-592` — append `&return_to=<encoded>` when `returnTo`
   (already sanitized at `:148-150`) is set; nothing else about the setup
   branch changes.
2. `MfaSetupPage.tsx` — read `return_to`, pass it through `sanitizeReturnTo`
   **again** (the module header of `lib/returnTo.ts` explains why both sides
   check; this page is a third side and gets no exemption), and after the
   `fetchCurrentUser()` tail do what `LoginPage.tsx:312-319` does:
   `window.location.assign(resume)` instead of `navigate("/dashboard")`.
   Factor that tail into a shared helper if the two copies would otherwise
   diverge. Strip the parameter from the URL with the same `replaceState`
   call that strips the token.
3. Tests: `MfaSetupPage.test.tsx` — a valid `return_to` resumes, an
   off-origin or malformed one is dropped and lands on `/dashboard`;
   `LoginPage.test.tsx` — the setup navigation carries it. The e2e spec's
   mocked `403` gets the parameter.

### M-5 — setup token single-use (Sonnet 5, optional)

**Closes** R-E. Do this only if it costs less than a day; otherwise leave R-E
recorded as a known residual in T-32's text and say so.

Add a `jti` to `MfaChallengeClaims` when `purpose == "mfa_setup"`, and consume
it on the first successful `setup/enroll` (TOTP) or `setup/register/start`
(WebAuthn) — the call that *chooses* the factor — so a second party holding
the same token cannot replace a pending enrolment. Consumption store: the
same mechanism T-32's challenge-token consumption uses if there is one (read
`verify_mfa`, `service.rs:640+`, and T-32's mitigation before deciding);
otherwise the single-use token table that already backs email verification
(`repository.rs:2770` `delete_unconsumed_for_user` names it). `confirm` /
`finish` then require the *same* `jti` the enrolment consumed, so the pair is
bound. Tests: replayed `enroll` → `401`; `confirm` with a token whose `jti`
was not the one that enrolled → `401`; the happy path unchanged. Update
`MfaSetupPage.tsx:44-47`'s comment, which will then be true.

### C-1 — `POST /api/v1/certificates/sign-csr` (Opus 5)

**Builds** feature 2. **Decisions** D-3…D-6. **Threat:** new **T-268** (§7).

**Core** (`axiam-core/src/models/certificate.rs`): next to
`SignIntermediateCsr` (`:331-344`), with the same length-eliding `Debug`:

```rust
pub struct SignCertificateCsr {
    #[serde(default)] pub tenant_id: Uuid,   // from context, never the body
    pub issuer_ca_id: Uuid,
    pub csr_pem: String,                     // PEM PKCS#10, "CERTIFICATE REQUEST"
    pub cert_type: CertificateType,
    pub validity_days: u32,
    pub metadata: Option<serde_json::Value>,
}
```

Response is the existing `Certificate` — **not** `GeneratedCertificate`, which
has a mandatory `private_key_pem`. There is no key to return and no field to
leave empty.

**PKI** (`axiam-pki/src/cert.rs`): `CertService::sign_csr(org_id, input, max_validity_days) -> AxiamResult<Certificate>`,
a sibling of `generate` that shares its CA checks and validity arithmetic
(factor those out of `generate` rather than copying them; `generate`'s tests
are the regression net for the refactor). Rules, each of which is a test:

1. **Proof of possession.** `CertificateSigningRequestParams::from_pem` — it
   verifies the request's self-signature (`ca.rs:622-627` explains why that
   is the whole point). A malformed or unsigned CSR is `AxiamError::Validation`
   (400) naming the request, parsed *before* the blocking task, exactly as
   `sign_intermediate_csr` does at `:547`. Make `csr_common_name` `pub(crate)`
   and reuse it.
2. **Key policy (D-4).** Read the SPKI: Ed25519 → `KeyAlgorithm::Ed25519`;
   RSA with modulus ≥ 4096 bits → `Rsa4096`; anything else → 400
   "AXIAM signs Ed25519 and RSA-4096 keys; this request carries {what}".
   Test with an RSA-2048 CSR and a P-256 CSR — both must be refused, and the
   RSA-2048 case is the one `parse_ca_certificate`'s OID mapping would
   otherwise accept.
3. **Extensions (D-3, D-5).** Refuse a CSR carrying a `subjectAltName`
   request (400, message names the rule and the follow-up). Every other
   requested extension is discarded: `request.params` is overwritten with the
   leaf parameters `generate` builds (`cert.rs:246-259`: CN from the CSR,
   `IsCa::NoCa`, validity), plus `use_authority_key_identifier_extension`.
   Test: a CSR requesting `CA:TRUE` and `keyCertSign` comes out `CA:FALSE`
   with no key-usage extension — the leaf twin of
   `a_csr_that_asked_to_be_an_unconstrained_ca_does_not_get_to_be_one`.
4. **Tenant scope (T-98).** `tenant_id` from the authenticated context;
   `issuer_ca_id` resolved through `ca_repo.get_by_id(org_id, …)` as
   `generate` does; the issuer must be Active, in window, and hold a key
   (`store_for(custody)` gives the `External` refusal for free). Test the
   cross-organization CA → not found, and the revoked/expired CA → refused.
5. **Validity.** Same `max_validity_days` cap, same 825-day hard cap, same
   `issuer_bounded_validity_days` refusal with the real number.
6. **Custody.** DB custody: sign in `spawn_blocking` behind the semaphore
   with `Issuer::from_ca_cert_pem`, zeroize the parent key as `generate`
   does. **Vault custody:** read `vault_pki.rs:630-660` and Vault's
   `sign-verbatim` documentation *before* writing this branch. `sign-verbatim`
   honours the CSR's subject and SANs and, depending on request parameters,
   its key usages. With rule 3 having refused SANs, and with AXIAM stating
   `key_usage`/`ext_key_usage` explicitly in the request body (empty, for
   parity with the DB path), the certificate Vault returns must be
   byte-equivalent in every AXIAM-decided field to the DB path's. Test against
   the Vault mock `vault_pki_test.rs` uses: a CSR requesting `CA:TRUE` yields
   a leaf; the request body sent to Vault carries the CSR verbatim and the
   AXIAM-decided fields, nothing from the CSR's extensions. If parity cannot
   be established, refuse CSR signing under `vault_pki` custody with a
   message that says so, record it in the EXECUTED block and in T-268, and do
   **not** ship a Vault branch that honours requester extensions.
7. **Row.** `StoreCertificate` with `key_algorithm` from rule 2 and `subject`
   from the CSR's CN (what the certificate says, T-194's "the row and the
   certificate cannot disagree"). `fingerprint` over the DER. `metadata` as
   `generate`.
8. **Binding.** Nothing to change: `bind-certificate` and mTLS device
   authentication key on the fingerprint and the chain. One test in
   `axiam-pki/tests/mtls_test.rs` (or the api-rest binding test) that a
   CSR-signed `Service` certificate binds and authenticates like a generated
   one — that is the property the feature exists for.

**REST** (`axiam-api-rest`): handler `certificates::sign_csr` shaped like
`generate` (`handlers/certificates.rs:48-80`: `certificates:generate`,
`user.tenant_id`, the tenant's `max_certificate_validity_days`), route
`POST /api/v1/certificates/sign-csr` registered beside `/certificates` in
`server.rs` (same rate limiting), row in `permissions.rs`'s route table
(`:743-754`) so the route-coverage test stays green, notification mapping
`("POST /api/v1/certificates/sign-csr", "Success") => CertificateIssued` in
`notification_rule.rs:125-131`. While there: the review found `signing-cas`
and `signing-cas/sign-csr` have **no** notification mapping and **no**
HTTP-level test at all (`grep signing-cas crates/axiam-api-rest/tests` is
empty). Add `CaCertificateIssued`-style coverage only if such an event
already exists; do add one HTTP test for `signing-cas/sign-csr` — it is a
twenty-line copy of the new leaf test and the endpoint currently has none.

Integration tests in `axiam-api-rest/tests/certificate_test.rs`: happy path
(`201`, body has no `private_key_pem` key at all, `GET` returns it, it lists
with `bound_to: null`), each refusal above at the HTTP layer with its status,
`certificates:generate` required (the existing
`certificate_endpoints_require_auth` pattern), and the E2E permission matrix
fixture (`frontend/e2e/matrix/pki.spec.ts`) extended with one CSR-signed leaf
under `mx-signing-ca-a` so the matrix proves the permission row.

**Spec**: utoipa annotations (tag `certificates`, `201 Certificate`,
`400`, `401`, `403`, `404`); `./target/debug/axiam-server --dump-openapi > sdks/openapi.json`
(built `--no-default-features`, as the contract's export note requires);
`scripts/check-spec-digest.py --write`; `scripts/gen-management-registry.py`
after adding `("sign_csr", "POST", "/api/v1/certificates/sign-csr")` to the
`certificates` entry of `NAMESPACES` (`:278-286`), then `--check`. The
registry's `operation_count` goes 159 → 160; every SDK's surface test asserts
that number and will fail until F-1 lands — expected, and the reason F-1 is
one wave.

---

## 5. Admin UI work

### C-2 — "Sign a CSR" on the Certificates page (Sonnet 5)

1. `services/certificates.ts`: `SignCsrPayload { issuer_ca_id, csr_pem, cert_type, validity_days, metadata? }`,
   `certificateService.signCsr(payload): Promise<Certificate>`; unit test in
   `services.test.ts` asserting the path.
2. `CertificatesPage.tsx`: a second primary action **Sign a CSR** (`Upload`
   icon, as `SigningCaPanel.tsx:373-377`) beside *Generate Certificate*, gated
   by the same permission. Dialog: issuing CA select (reuse `GenerateFields`'
   CA select and its `maxValidityDays` derivation — extract the shared parts
   rather than duplicating them), certificate type, validity days, and the
   CSR itself as **both** a textarea and a file input
   (`<input type="file" accept=".csr,.pem,.txt,application/pkcs10">`, read
   with `File.text()`, filling the textarea so the user sees what will be
   sent). Client-side check is only `BEGIN CERTIFICATE REQUEST` — the same
   one line `SigningCaPanel.tsx:409-414` does, for the same reason its
   comment gives; note in the helper text that `BEGIN NEW CERTIFICATE REQUEST`
   (the legacy OpenSSL header) is not accepted, since `rcgen` does not parse it.
   No key algorithm field: the key is the caller's. Server `400`s render
   inline, verbatim — they are written to be read.
3. Result: straight to `CertificateViewDialog` (download buttons for the
   certificate and chain). **Never** `SecretRevealModal` — there is no secret.
4. `SigningCaPanel.tsx`: add the same file input to the existing CSR textarea
   for consistency (small, optional; if done, the test
   "rejects a paste that is not a certificate signing request" gains a file
   twin).
5. Tests in `CertificatesPage.test.tsx`: dialog opens, a paste and a file
   upload both submit the same body, a non-CSR paste is refused client-side,
   a server `400` is shown verbatim, success opens the view dialog and never
   the secret modal (assert the modal's label is absent from the DOM).
   `frontend/e2e/certificates.spec.ts` gets one CSR case against a real
   server if the suite has a signing CA fixture; otherwise the matrix case in
   C-1 covers it.

---

## 6. Contract, docs and website

### C-3 — contract 1.45, PKI guide, website, threat model (Sonnet 5)

Runs after M-3 and C-1 have merged; F-1 re-vendors what this produces.

1. **`sdks/CONTRACT.md`** — one version bump, **1.45**, additive:
   - §27.1: `certificates` | 5 ops | `list`, `generate`, `sign_csr`, `get`, `revoke`;
     the preamble sentence about `generate` marking "the server mints key
     material" gets its counterpart: `sign_csr` marks "the caller did".
   - §27.5: state that `sign_csr`'s response has **no** sensitive field, and
     that an SDK MUST NOT reuse the `GeneratedCertificate` model for it (a
     type with a mandatory key field that is always absent is a type that
     lies).
   - §24.1, §24.7, §24.8, §25.1, §25.2 — the M-3 text.
   - §5.2 — the M-2 sentence.
   - Breaking Changes Log: one entry, "2026-09 (contract 1.45) —
     **non-breaking / additive**", listing the three additions and stating
     that no existing name changes meaning.
   - §27.10 per-SDK posture: unchanged; the fan-out record lives here in §9.
2. **`docs/pki/README.md`** — under "Issue a leaf certificate" (`:430`), a
   subsection "Or bring a CSR" with the rules of C-1 as an operator reads
   them (possession proved, subject kept, extensions and SANs refused or
   dropped, key policy, no key in the response, custody note), and a `curl`
   twin of the walkthrough at `:588+`. The "What `vault_pki` does not remove"
   paragraph (`:424-428`) needs its last sentence amended: leaf keys are
   generated by AXIAM *unless the caller brings a CSR*.
3. **Website** — `website/src/docs/operate.ts:555-572`'s CSR paragraph and
   endpoint table gain the leaf row; `website/src/apiIndex.ts` the path;
   `website/src/docs/authentication.ts:106` (the three-outcome sentence) gains
   "and the setup token now enrols a passkey or a security key as readily as
   TOTP"; the MFA page linked from it gets the chooser. `docSectionsAreComplete()`
   must stay green; `scripts/check-website-links.py`.
4. **`CHANGELOG.md`** — under `[Unreleased]`: **Security** (M-1, M-2),
   **Added** (M-3, C-1/C-2), **Changed** (M-4, M-5 if done), each in the house
   style: what a client or an operator observes, and why.
5. **Threat model** — §7.

---

## 7. Threat-model bookkeeping

Allocate from `threatTop` (266), never from a section's last number
(`threat-model-stride.md` §9). Model version 2.14.0 → **2.15.0**. Update
`ThreatDragonModels/Axiam/Axiam.json`, `claude_dev/threat-model-stride.md`
(§5.2 and §5.6 tables and entries, §6 register) and
`claude_dev/threat-modeling-and-security.md`; run
`node website/scripts/gen-threat-model.mjs`, confirm the printed counts, and
handle its generated output the way the 2026-09-12 pass did (it reverted the
generated files and committed the model).

| # | Section | Element | STRIDE | Title | Severity | Status on landing |
|---|---|---|---|---|---|---|
| T-267 | §5.2 | MFA verification TOTP / WebAuthn | E | A user lowers their own account below the tenant's MFA floor through self-service reset | High | Mitigated by M-2 |
| T-268 | §5.6 | Certificate issuance (rcgen, policy enforcement) | E | Leaf CSR signed with the requester's extensions, a weak key, or onto a key the requester does not hold | High | Mitigated by C-1 |
| T-269 | §5.2 | MFA verification TOTP / WebAuthn | E | A setup token enrols a passkey on an account that already has a factor, or one the tenant's authenticator policy forbids | High | Mitigated by M-3 |

Amend, without changing status: **T-34** (mitigation gains "the reset removes
WebAuthn credentials as well as the TOTP secret" — M-1; until M-1 lands, the
honest text is the residual, so write the residual first if M-1 slips),
**T-32** (M-5's outcome, either way), **T-201** and **T-229/T-230** (forced
setup uses the same registration policy path — M-3), **T-194** (cross-reference
T-268), **T-96** (the CSR modulus check — C-1). Open register count moves
only if a residual is recorded as Open; the intent is that none is.

---

## 8. Follow-ups deliberately not in this plan

- **Fresh-authentication requirement for self-service MFA changes** (D-1's
  alternative): `max_age`-style recency on the session for `reset-mfa` and
  `mfa-methods` delete, with the admin UI's existing re-auth hop
  (`lib/reauth.ts`) as the client half. Belongs with OIDC `max_age` support.
- **SANs on leaf certificates** (D-3): an allow-list per `cert_type`
  (dNSName for `Service`, none for `User`, an operator-configured pattern for
  `Device`), applied to *both* the generate and the CSR paths.
- **KU/EKU profiles per `cert_type`** (D-5): `clientAuth` for `User` and
  `Device`, `clientAuth` + `serverAuth` for `Service`, digitalSignature (and
  keyEncipherment for RSA) — decided once, for both paths, with a migration
  note for certificates already issued without them.
- **Recovery codes.** None exist anywhere in the codebase; a user who loses
  their only factor depends on an administrator. Out of scope here, recorded
  because the review looked for them.
- **`mfa_setup_reminder` email.** The template type exists
  (`email_template.rs:81`) and nothing sends it. An enforcing tenant could
  mail users who have not completed setup; separate item.
- **Notification event for signing-CA issuance.** No mapping exists for
  `signing-cas` or `signing-cas/sign-csr`; add `CaCertificateIssued` if
  operators want it.

---

## 9. SDK fan-out — F-1 (Sonnet 5, one wave, eleven repositories)

The rules of [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md)
§13 bind here verbatim; the toolchain notes in its §13.1 (`dotnet-sdk-8.0`
from apt; PHP `--no-dev --prefer-source` plus apt `phpunit`; no Swift
toolchain in the sandbox, CI-verified only) are still accurate and save a
day. Read each SDK's `CLAUDE.md`, README conformance section and CI workflow
first.

Per repository, one branch named for this plan, one PR:

1. Re-vendor `CONTRACT.md` (1.45), `openapi.json`, `management-registry.json`,
   `proto/` from the `axiam` commit that carries C-3.
2. **C-1 (mechanical):** run the SDK's generator (`tools/gen_management.py`,
   `scripts/gen-management.mjs`, `scripts/gen_management.py`,
   `internal/cmd/genmanagement`, `Scripts/gen_management.py` — the table in
   the remediation plan names each). Commit the output. The surface test's
   operation count moves 159 → 160. Add the `SignCertificateCsrRequest`
   model where the generator does not emit models (check
   `management/models.*` — some SDKs hand-write them). Response model is the
   existing `Certificate`, per §27.5's new sentence; assert in the model
   round-trip test that the `sign_csr` return type has no key field.
3. **M-3 (mirror):** two JSON-bridge helpers beside the existing
   `webauthn_register_start` / `webauthn_register_finish` (§24.6 linked-API
   helpers), taking the setup token, the `finish` adopting credentials exactly
   as `mfa_setup_confirm` does (§25.2 rule 2, §24.3's five adoption rules,
   §17 memo cleared). §24.8's new test. Kotlin, Swift, C and C++ carry the §24
   protocol core per §24.7 — same shape, no ceremony.
4. Per-SDK drift check, contract-conformance suite, linter, full test suite,
   the way CI runs them. `CHANGELOG.md` under `[Unreleased]`, one entry per item.
5. **Do not tag or publish.** Once all eleven are open, re-vendor the final
   `CONTRACT.md` into every branch as its own commit (the §13.1 ordering note
   applies whenever a per-SDK table row is filled — none is planned here, so
   this should be a no-op; check).

### 9.1 Fan-out record

| SDK | C-1 `sign_csr` | M-3 setup helpers | PR | CI at session end |
|---|---|---|---|---|
| rust | | | | |
| typescript | | | | |
| python | | | | |
| java | | | | |
| kotlin | | | | |
| csharp | | | | |
| php | | | | |
| go | | | | |
| swift | | | | |
| c | | | | |
| cplusplus | | | | |

---

## 10. Order, branches and PRs

1. **M-1, M-2, M-4** — small, independent, no contract dependency; one
   `axiam` branch, one commit each, one PR. Merge first: two of them close
   security residuals and nothing below depends on them.
2. **C-1** on its own branch and PR (server + spec + tests). It is the largest
   server item and the one a reviewer wants to read alone.
3. **C-2** on its own branch, opened once C-1 is pushed (it needs the route).
4. **M-3** on its own branch and PR (server + UI + contract text). M-5 rides
   this PR if done, because it touches the same token code.
5. **C-3** — contract 1.45 bump, docs, website, threat model — one commit,
   after M-3 and C-1 merge. Nothing in F-1 starts before this is pushed.
6. **F-1** — eleven PRs, record in §9.1.

Every PR: opened by the agent on behalf of the maintainer, referencing the
issue(s) it addresses (open two issues first if none exist — the review found
#84 *T14.1 MFA Enforcement & First-Login Flow* and #86 *Multi-MFA Method
Management*, both closed, for feature 1, and **no** issue for CSR issuance),
with a description that names the plan item and the tests that prove it.
Signed commits, per the repository's process. Issues close on merge.

---

## 11. Kick-off prompt for the implementing session

Paste as the first message of an **Opus 5** session opened on `ilpanich/axiam`
with the eleven SDK repositories attached:

```
Execute claude_dev/mfa-first-login-and-csr-issuance-plan.md.

Read it in full first, then CLAUDE.md (especially "Build & Disk Hygiene"),
then claude_dev/remediation-plan-2026-09-12.md §13 for the SDK fan-out rules.
Do not re-derive the review in §1; it was verified against main at 9a5ba6a.
Section §3 lists decisions already taken — follow them unless the plan says
they were overridden.

Work the items in the order of §10. For each item, prepend an EXECUTED block
to its section when it lands, in the form remediation-plan-2026-09-12.md uses.
Do M-1, M-2 and M-4 yourself or through Sonnet 5 subagents; do C-1 and M-3
yourself (they change credential and session issuance and need the design
judgement the plan asks for — in particular C-1 rule 6 on Vault custody and
M-3 rule 4 on AMR evidence). Delegate C-2, C-3, M-5 and the eleven F-1
repositories to Sonnet 5 subagents, one repository per agent, with the
plan's §9 and the SDK's own CLAUDE.md as their brief; fill §9.1 as PRs open.

Rules that are not negotiable: every commit passes fmt, clippy -D warnings,
the layering and doc-link scripts; every server change lands with its tests
and its threat-model bookkeeping (§7) in the same commit; the OpenAPI spec is
regenerated with --dump-openapi and re-stamped, never hand-edited; no SDK is
tagged or published; cargo clean between Rust items. One contract version
(1.45) and one SDK wave, at the end. Open PRs on behalf of the maintainer,
referencing issues (open the two issues §10 describes if they do not exist),
and subscribe to each PR's activity.

If a task cannot be completed as specified, finish every other part, record
what was left and why in that section's EXECUTED block, and say so in the
final report. Report at the end with: what merged, what is open, the §9.1
table, and any decision in §3 you had to revisit.
```

---

**References** — [`roadmap.md`](roadmap.md) T14.1 · [`design-document.md`](design-document.md) §8c.1 ·
[`threat-model-stride.md`](threat-model-stride.md) §5.2, §5.6, §9 ·
[`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) §13 ·
[`basic-op-gap-plan.md`](basic-op-gap-plan.md) §4 ·
[`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) §5.2, §24, §25, §27 ·
[`../docs/pki/README.md`](../docs/pki/README.md) ·
[`../docs/admin/authenticator-policies.md`](../docs/admin/authenticator-policies.md)
