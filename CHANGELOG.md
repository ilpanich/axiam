# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `just prod-up` could rotate every Vault secret on a running stack

  The seeder's one invariant — a secret already present is never regenerated —
  was enforced by a pure function that has always been correct, behind a shell
  line that was not: `curl --fail ... || echo '{}'` turned *every* failed read
  into "the Vault is empty". Vault with Raft storage returns from `sys/unseal`
  while the node is still a standby contending for leadership, and `prod-up`
  seeded immediately after unsealing — so on a restart-driven run the read could
  be refused, a full set of new keys minted, and the write land moments later
  over the live ones. It reported `→ Seeded` and exited 0. From then on every
  login answered `500` with

      Cryptography error: AES-GCM decrypt: aead::Error

  because `opaque_setup_key` no longer opened the OPAQUE records the datastore
  held. A revoked or write-only token produced the same outcome deterministically.

  `scripts/vault-seed.sh` now waits for an **active** node (not merely a
  listening or unsealed one), passes the read's HTTP status to the payload
  builder so that only `200` or `404` may be read as a statement about the
  contents, and pins the write with KV v2's `cas` to the version it read.
  Anything else stops the seeder with nothing written. `just prod-up` waits for
  `sys/health` to answer `200` after unsealing, before it seeds.

  A replaced key is usually recoverable: KV v2 keeps ten versions, and
  `docs/deployment/vault.md` §8.1 has the `vault kv patch` restore, which costs
  no password resets.

### Changed

- The Vault seeder's tests now run in CI

  `scripts/test_vault_seed_payload.py` guarded "a password reset for every user
  in every tenant" and ran nowhere. It is now part of the Architecture
  Invariants job, alongside a new `scripts/test_vault_seed_shell.py` that drives
  the real script against a Vault answering `500`, `503`, `403` and `404`, and
  asserts on what was written rather than on an exit code.

## [1.0.0-beta10] - 2026-09-03

### Changed

- Grant the server's Vault token the CA-key writes it needs (#412)

- Bump qs

- `just vault-status` reports missing capabilities, not only excess ones

  It probed two paths and called anything beyond `read` over-scoped, so a token
  that could not write a CA signing key reported `ok`. It now probes the CA-key
  paths too, knows what each path is supposed to grant, and prints `MISSING`
  with the capabilities a token lacks.

- A refused Vault call names the policy rule it needs

  A `403` from CA key custody now prints the missing stanza as HCL, addressed to
  the mount and prefix that deployment configured. Other statuses are unchanged:
  a sealed Vault is not a policy problem and is not reported as one.

### Fixed

- CA generation refused with `403 Forbidden` on a Vault-backed deployment

  The Vault policy `just prod-up` wrote — and the one documented as the
  production ceremony — granted `read` on `secret/data/axiam` and nothing on
  `secret/data/axiam/ca-keys/*`, where CA key custody writes one secret per CA.
  Since custody inherits `AXIAM__AUTH__VAULT_ADDR` / `_TOKEN` when no
  `AXIAM__PKI__VAULT_*` pair is set, every such stack booted cleanly, served
  every request, and then refused its first organization CA.

  The policy now lives in `docker/vault/axiam-policy.hcl` — one file, applied by
  `scripts/vault-policy.sh`, quoted by the docs and asserted against by the
  status reporter's tests. `just vault-policy` applies it to a **running**
  deployment: Vault evaluates policies per request, so nothing needs restarting,
  re-initialising or re-seeding, and nothing already stored is lost.

## [1.0.0-beta09] - 2026-09-02

### Changed

- Pin the tenant a check is evaluated in

- Allow the ninth argument on start_registration_for_policy

- Regenerate the OpenAPI spec for the WebAuthn policy field

- Port the grpc 1.83.1 bump from #407 to unblock CI

- Gate that every COPY source survives .dockerignore

- Bump google.golang.org/grpc

### Fixed

- The effective-access preview evaluated in the wrong tenant

- Refresh against the tenant the caller lives in

- A scope grant inherits down the resource hierarchy

- The remaining test callsites the last pass missed

- The three gates the first push missed

- Make user verification a policy instead of a hard-coded constant

- An unscoped role assignment grants tenant-wide, not nothing

- Let Vault write its Raft volume in the prod Compose stack

- Bump x/net and x/text past the CVEs this PR surfaced

- Keep nginx.conf.template in the frontend build context

## [1.0.0-beta08] - 2026-09-01

### Added

- Raft-backed Vault, a scoped server token, and loopback binds

- Template the frontend's backend upstream so it can speak TLS

- Hot-reload the TLS leaf certificate, so ACME renewal needs no restart

- "Sign in with X" buttons, the SSO callback route, and the admin fields

- The public login-provider surface — buttons, OAuth2, handoff codes

- The OAuth2 variant, PKCE, Apple secrets and templated issuers

- Provider kinds, the OAuth2 variant, inheritance and claim mapping

### Changed

- Keep argon2 0.6 out of the wasm getrandom trap

- Migrate password hashing to the argon2 0.6 API

- Cover the reload mechanism, not just the pieces either side of it

- Say what the reload poll actually compares

- Six threats for the publicly exposed backend

- The path-split topology, TLS renewal, Raft, and the TRUSTED_HOPS off-by-one

- Rewrite the Pi runbook for the new topology, a real Vault and the buttons

- The public backend, its own TLS, and the hop that broke the limiter

- Bump the minor-patch group across 1 directory with 5 updates

- Cite the archived Phase 25 plan by path instead of linking it

- Drop response-derived values from assertion messages entirely

- Bump argon2 from 0.5.3 to 0.6.0

- Bump docker/setup-buildx-action from 4.2.0 to 4.3.0

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 10 updates

- Bump actions/checkout from 4 to 7

- Bump hadolint/hadolint-action from 3.4.0 to 3.5.0

- Stop assertion messages printing cookies and response bodies

- Cover the OAuth2 failure paths, the handoff repo and the icon field

- Name the four login-provider operations in the §12.2 map

- Threat model, contract 1.37, roadmap and the icon design

- Design the "Sign in with X" login providers

- Record the beta07 website pass against its plans

- Re-verify the docs section and stamp it at 1.0.0-beta07

- Link the normative docs the site never pointed at

- A passkey is a factor, and lockout reads the tenant's policy

- Bring the PKI pages up to the tenant-CA and trust-anchor model

- Cover the management API, and correct the REST conventions

- Document organization-level principals

- Announce the beta phase, and stop calling beta future

- Regenerate the API index and contract anchors at beta07

### Fixed

- Record why the trust-store package is not version-pinned (DL3018)

- Stop trusting a forwarded client certificate by default

- TRUSTED_HOPS is proxies minus one, not proxies

- Confine handoff redirects to this deployment, and follow inheritance at the SAML ACS

## [1.0.0-beta07] - 2026-08-30

### Changed

- Archive phase directories from completed milestones

- Updated .gitignore

- Quick task — bench lockout policy neutralization

- Plan the cumulative beta06 docs catch-up pass

- Record the beta05…beta06 wave — T-200…T-211, model 2.10.0

### Fixed

- Name the k6 setup() exception in the dry-run verdict

- Neutralize the lockout POLICY, not just the deployment default

## [1.0.0-beta06] - 2026-08-30

### Added

- Assigning a role from a user or a group can name its scopes

### Changed

- Mint the child-tenant password into a static, like its two siblings

### Fixed

- The acting-tenant header is `X-Axiam-Tenant`, not `X-Tenant-ID`

- The admin UI was showing the wrong tenant's data, or none at all

## [1.0.0-beta05] - 2026-08-30

### Added

- A role assignment can name the tenants it reaches

- Tenant-scoped role assignments: an organization-level account can now be
  confined to particular tenants of its organization. `tenant_scope` on the
  three assignment endpoints names the tenants an assignment reaches;
  `reachable_tenant_ids` on `/auth/me` reports the result. Such an account is
  refused organization-level actions, sees only the tenants it reaches in the
  tenant roster, and is refused `X-Axiam-Tenant` for any other. Schema 51,
  additive with no backfill — every existing assignment stays unrestricted.

### Changed

- Creating an organization or a tenant needs an organization principal

- Revert "fix(authz): a tenant scope narrows reach across tenants, not within one"

- Undo a gratuitous reformat of the nav destination table

- The nav matrix has to know that one gate is not a permission

- Six suites need an organization principal, and a real trust anchor

- Track the matrix runbook, in claude_dev where it belongs

- The organization lifecycle tests need an organization principal

- Let the typecheck see the suite that reads the repo

- Record wave 4 — the four open items, and what closing them found

- Measure the in-page gates that only exist after a selection

- Read the mail publishers instead of quoting them

- Record wave 3 — the unverified half, and what closing it turned up

- Reuse the captured session instead of signing in mid-test

- Close three gaps where the matrix was measuring nothing

- Measure the mTLS handshake half of §4

- Assert no mail template leaves a placeholder standing

- Sharpen the mTLS and matrix assertions; wave 2 is clean

- Stop asserting one locale's number formatting; add the mTLS check

- Record wave-1 findings and the fixes applied

- Tenancy, group inheritance, service-account and PKI matrix + mail checks

- RBAC/PKI permission matrix harness against the prod stack

- Record the Sigstore half of H-1 as landed (T-148)

### Fixed

- User creation was the next ceiling, for the same reason

- The test stack was one login away from red

- B5's login failure was unreportable, not just failing

- A restricted organization principal can read its own reach

- A tenant scope narrows reach across tenants, not within one

- The preview proxy was swallowing /auth/mfa-setup

- Refresh the management registry's spec digest

- Clear the six failing gates on the E2E matrix branch

- A passkey is a factor, so enrolling one requires MFA

- Stop telling a tenant super-admin it can do everything

- Type the captured request bodies, and make tsc a gate over the specs

- Stop seeding organization-level actions into tenant roles

- Stop a second replica logging out the first, and recover when it happens

- Require a certificate to chain to a CA enabled as an mTLS trust anchor

- Gate the Audit Logs nav entry, and keep the selected tenant

- Make first-run and tenant provisioning idempotent and honest

- Stop demanding a CSRF cookie from a bearer-only caller

- Confine organization-level actions to organization-scoped principals

- Stop nginx swallowing /oauth2-clients into the OAuth2 proxy

- Organization scope, OPAQUE enrolment tenancy, settings inheritance, and RBAC for service accounts (#393)

- Enrolling a passkey or a security key now makes multi-factor authentication
  **required** at sign-in, the way confirming an authenticator app always did.
  The credential was listed on the profile page and accepted at
  `/auth/webauthn/authenticate`, but the login gate reads `mfa_enabled`, which
  only `confirm_mfa` ever set — so an account whose sole factor was a passkey
  signed in with a password and nothing else.

- The admin UI no longer renders organization-level controls to principals the
  server refuses them to. A tenant's `super-admin` holds the whole permission
  registry, so no permission check could have hidden "New Organization", the
  tenant lifecycle buttons or the CA controls; the gate is now the same
  standing the server checks.

- `GET /organizations/{org}/tenants` returns only the tenants the caller may act
  on. Every principal holding `tenants:list` previously saw every tenant of the
  organization, including a tenant administrator whose reach is one tenant.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Record what H-1 actually landed per repo, and the pinning gotcha

### Fixed

- Re-vendor the spec into every SDK repo as part of the release

- Keep secret names out of the response-derived data flow

## [1.0.0-beta03] - 2026-08-28

### Added

- Close T-118, make the Vault posture checkable, attest release artifacts

### Changed

- Answer the pre-beta03 question — no fix required, plan the hardening

- Plan the docs-section beta03 catch-up, wave by wave

- Record the beta01…beta03 wave — T-187…T-199, model 2.8.0

### Fixed

- Build each removal cookie from the setter it mirrors

- A removal cookie must mirror the cookie it clears

- Let an organization-level principal sign in again

- Re-stamp the spec digest the release bump invalidated (#387)

## [1.0.0-beta02] - 2026-08-27

### Added

- Search and paging on every list, and say what a grant reaches

- Organization-level principals

### Changed

- Say what "no body" has to be asserted on

- Contract 1.31 — the PR #383 surface, stated for the SDKs

- Pin filter parsing and the degenerate userName page

- Cover CA import validation and the SCIM token principal

- Cover the Groups collection and the PUT deprovisioning path

- Pin the CA custody decision the beta got wrong

- Cover the mTLS trust-anchor hot reload

- Record §27 as implemented in all eleven SDKs (#385)

- Update three assertions to the behaviour this PR ships

- Give every OpenAPI export a content digest, so two can be told apart (#384)

- Update three Playwright specs to the behaviour this PR ships

- Regenerate the OpenAPI spec and management registry

- Import SubjectScope where the suites construct it

- Thread TenantKind and SubjectScope through the suites

- Organization scope, Vault inheritance, mTLS hot reload

### Fixed

- A projected list element is not an anonymous type

- Stop migrating a CA into database custody from destroying its key

- Drop two unused SubjectScope imports

- Assign b6's tenant admin through the role, not the user

- Sign the fixture admin in by username, drop the new password literal

- Wire the tenant resolver and reseat the examples on organization scope

- Build clean under -D warnings, and cover the new frontend modules

- Satisfy oxlint on the paginated pages

- A resend button that says what happened

- Make cross-tenant reach a claim, not a coincidence

- Resend verification, unique seeded scopes, quiet shutdown

- Inherit the configured Vault for CA signing key custody

## [1.0.0-beta01] - 2026-08-26

### Added

- Classify PUT bodies as sparse update or full replacement

- Derive the §27 management vocabulary from openapi.json

- An organization CA can anchor mTLS, and its key can move to Vault

### Changed

- Add CONTRACT §27 — the management API

- Request 365, not 800 — a bigger number never reaches the issuer check

- Three suites were asserting the behaviour this PR set out to fix

- Generate fixture passwords instead of hard-coding them

- Document AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH

### Fixed

- Clippy errors, and use the lockout helper the tests were missing

- Erase a deleted user's personal data, and free their identifiers

- Guarantee no template placeholder ever renders literally

- Carry the CA's expiry into the certificate form's CA option

- Every template greeted the reader with "{{username}}"

- Stop the random logouts, the stale views, and the nameless scope chip

- Make Delete remove a user, seed a default scope, and sync the sidebar

- Send the activation mail, and make notification rules actually fire

- Lock accounts on the organization's threshold, not the deployment default

- RSA-4096 keygen, and refuse a certificate that outlives its issuer

## [1.0.0-alpha44] - 2026-08-25

### Added

- Hand over the certificate, and manage a tenant's signing CAs

- Tenant signing CAs, signed by the org CA and kept in Vault

- Sdk-dry-run — rehearse all eleven SDK benches in minutes

### Changed

- Cover the copy, focus-trap and revoke paths; sync openapi.json

- Bump scrypt from 0.11.0 to 0.12.0

- Bump the minor-patch group with 3 updates

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 7 updates

- Bump softprops/action-gh-release from 2 to 3

- Bump actions/download-artifact from 4 to 8

- Bump actions/upload-artifact from 4 to 7

- Bump actions/setup-node from 6 to 7

### Fixed

- OPAQUE never ran in the browser; build the wasm from source

- A tty stdin let the Kotlin bench hang the whole SDK sweep

- Empty BENCH_ORG_ID made every token_refresh call a 400

- Box the DPoP error so the token path clears result_large_err

- Exempt the three form-seeding effects from set-state-in-effect

- Drop the removed length argument from scrypt::Params::new

## [1.0.0-alpha43] - 2026-08-24

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha42.

## [1.0.0-alpha42] - 2026-08-24

### Changed

- Update .gitignore

### Fixed

- Fold the pending [Unreleased] block into the release being cut

- Drain a rate-limited call's body so h2 stops killing the connection

- Retry the failed-login accrual when it loses a write conflict

## [1.0.0-alpha41] - 2026-08-24

### Added

- Let Vault generate the CA and its signing intermediate (#368)
- Put CA signing keys in Vault, and let an organization bring its own
- Working tenant switcher, opaque menus, a way out of the no-CA dead end
- Make the erasure window a setting and the tenant overrides visible

### Changed

- Exercise the Vault CA key store against a real HTTP server
- Document the six CA key custody variables

### Fixed

- Do not refuse to boot when no CA key custodian is configured
- Make enabling OPAQUE actually enable it
- Make the tenant cascade work, and let an operator prove delivery
- Page list endpoints to the end instead of taking the first 50

## [1.0.0-alpha40] - 2026-08-23

### Added

- Resource-scoped role assignment in the admin UI
- Expose role assignments with the resource they are scoped to
- Close the request-shape gaps an OpenAPI sweep found
- Make the OPAQUE policy settable from the admin UI

### Fixed

- Refuse a settings write that enables OPAQUE without server keys
- Give .glass-card the padding it never had
- Exempt the WebAuthn authentication ceremonies from CSRF

## [1.0.0-alpha39] - 2026-08-23

### Added

- Gate the configuration page against the keys the server reads

- Rate-limit the WebAuthn ceremony routes

### Changed

- Give federation a setup procedure and service accounts an audience warning

- Stamp docs pages per page, not per section

- Walk the code flow, and open the token up

- Show OPAQUE through an SDK, and how each one binds it

- Resolve one tree node by node on the authorization engine page

- Give the operate pages the data they were describing

- State what the config reference covers, and add the keys it lacked

- Add the tutorial that bridges quickstart and core concepts

- Turn SCIM into a walkthrough, and fix what it said about the token

- Show the AMQP topology and one signed message

- Deepen the gRPC page to the surface the server actually serves

- Back the compliance claims with links, and generate contract anchors

- Follow up on #362 — model carries T-182's clause, site documents the throttle

- Index the GDPR endpoints, and fix two summary-extraction bugs

- Say precisely what PUBLIC means on an OAuth2 route

- Generate the REST endpoint index from the OpenAPI document

- Add the missing pushed-authorization page

- Record the rate-limit gate T-182 did not re-establish

- Lead every code sample with Rust

- Bring the passkey, MFA and lifecycle pages up to contract 1.28

- Give the Client SDKs page the matrix and the code it lacked

- Correct and complete the webhook page

- Show the reactor registry instead of describing it

- Put coverage, the open risk register and the evidence on the page

- Make the threat model citable — IDs, deep links and filters

- Emit STRIDE, severity and open-risk data from the threat model

- Plan the docs-section deepening, page by page

- Record the contract 1.28 SDK surface and the passkey cookie fix

### Fixed

- Repair §14.1's link to the device_login heading

- Classify the GDPR paths for the route ↔ OpenAPI parity check

- Register the GDPR endpoints in the OpenAPI document

- Bring the harness and quick runbook up to alpha38

- Benchmark harness and quick runbook brought up to alpha38. The two `opaque_*`
  cells could not pass — missing from `AXIAM_ONLY_SCENARIOS`, so they ran
  against Keycloak and Zitadel and failed in `setup()`, and the bench tenant
  left `opaque_mode` disabled so they 404'd against AXIAM too. `bench-quick`'s
  reactor probe had gone stale into a false negative. `rl_prod_check.py` had
  rows for eleven of sixteen REST rate-limit families, with five absent rather
  than reported unchecked.

### Security

- Rate-limit the six `/api/v1/auth/webauthn/*` ceremony routes. They carried no
  limiter at all — no governor, no shared counter, and no `webauthn_per_min`
  knob existed — while the MFA routes directly above them and the OPAQUE routes
  directly below each carried one. Two of the six are the unauthenticated
  usernameless sign-in path. New `AXIAM__RATE_LIMIT__WEBAUTHN_PER_MIN`,
  defaulting to 10 and applying to each of the six routes independently —
  deliberately the same per-IP sign-in allowance `login_per_min` already
  grants passwords.

## [1.0.0-alpha38] - 2026-08-22

### Changed

- §8b names an enforcement point for Swift, C and C++
- §24.4 rule 1 does not license dumping a response body
- Split §24.6 into a JSON bridge and a linked-API helper
- Add §24 WebAuthn, §25 account lifecycle, §26 PAR; narrow §22.11
- Carry two review details into the Security section
- Record the alpha37 closures, and the passkey sign-in path

### Fixed

- Set session cookies when a passkey ceremony completes

## [1.0.0-alpha37] - 2026-08-21

### Added

- Close T-132, T-131, T-129 and T-153
- Enforce a default audit retention policy (T-119)

### Changed

- Re-export openapi.json for the T-153 metadata_stale deny reason
- Re-export openapi.json after the RefreshRequest org_id change
- Cover the two 0% model files, the settings diff, and the reactor bridge
- Bring the Security section up to alpha34
- Bring the STRIDE model up to alpha34

### Fixed

- Make usernameless passkey sign-in actually work
- Treat npmjs.com as bot-hostile in the website link check
- Repair four broken SDK doc links and check them on a schedule
- Apply the SEC-053 ingress policies, and close three stale threats
- Repair token refresh, passkey origin, and the login-page bounce
- Make prod teardown work and refuse to mint creds for live volumes

## [1.0.0-alpha35] - 2026-08-21

### Added

- `AXIAM__AUTH__VAULT_CA_CERT_PATH` — trust anchor for a Vault fronted by a
  private CA. rustls compiles its roots in, so an internal PKI (cert-manager,
  `just tls-certs`) was previously unverifiable and the server panicked at
  startup with a bare transport error.

### Changed

- Justfile prod-up to use official images instead of local builds.

- Threat model brought up to `1.0.0-alpha38`: the contract 1.28 SDK surface —
  WebAuthn (§24), account lifecycle (§25), PAR (§26) and the Swift/C/C++
  reactor protocol core (§22.11) — is recorded as four new mitigated threats on
  the SDK diagram (T-183…T-186, 186 threats total, 170 mitigated / 16 open),
  T-182 notes the passkey session-cookie fix, and the website Security section
  (`src/security.ts` plus the generated model files) is updated in step.

- Website Security section brought up to `1.0.0-alpha34` from
  `claude_dev/threat-modeling-and-security.md`: OPAQUE (RFC 9807) as an
  optional augmented PAKE, Vault as the production secret provider, TLS-only
  AMQP, purpose-bound SCIM provisioning tokens, sender-constrained OAuth2
  clients and tokens (mTLS, `private_key_jwt`, DPoP, RFC 9207), the WebAuthn
  MDS3 attestation policy, and the SurrealDB persistent-storage-engine
  requirement. Deny-override shipped (SEC-040, T-16/T-87), so it is no longer
  listed as an accepted trade-off.

### Fixed

- Make `just prod-up` able to bring the stack up

- `just prod-up` could not start any stack: `${AXIAM_IMAGE_TAG:latest}` is not
  valid Compose interpolation, the SurrealDB and RabbitMQ credentials the
  compose file requires were never generated, and `AXIAM__AUTH__VAULT_TOKEN`
  was demanded before the Vault that issues it existed.

- Vault's listener key was mode 0600, unreadable to uid 100 in the container,
  so the Vault service restart-looped on "error loading TLS cert".

- Vault's port is published on loopback, which `prod-up` needs to initialise,
  unseal and seed it from the host.

- A Vault init that failed mid-write left an empty `vault-init.json` that
  wedged every later run; initialisation is now driven by Vault's own
  `sys/init` status and validated before it replaces the state file.

## [1.0.0-alpha34] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha33.

## [1.0.0-alpha33] - 2026-08-21

### Added

- Seed every AXIAM secret into Vault, minting what is missing (#350)

### Changed

- Correct the SDK and HTTP samples against the real APIs
- Rebuild the documentation section for a production IAM
- The baseline resolved in step 3b is OPAQUE's, not SRP's
- Publish axiam-opaque via Trusted Publishing, not tokens

### Fixed

- Pin axiam-opaque's MSRV explicitly, and gate its vendored copy
- Cut axiam-opaque on the tag release-opaque.yml triggers on

## [1.0.0-alpha32] - 2026-08-20

### Added

- HashiCorp Vault in the stack, mandatory in production
- Pluggable secret provider for the OPAQUE keys, and a release pipeline
- Migrate the admin UI from SRP to OPAQUE
- C ABI and WebAssembly builds of the shared client core
- OPAQUE endpoints, enrolment rework and the shared client core
- Implement the OPAQUE protocol engine and persistence
- Replace the SRP domain model with OPAQUE (RFC 9807)
- `crates/axiam-opaque` (layer 0): the single definition of AXIAM's OPAQUE
  ciphersuite, key-stretching functions and client operations, bound by every
  SDK and the admin UI. OPAQUE is not a protocol it is reasonable to hand-write
  once per language, which is what SRP's eleven implementations required.
- Schema v42: `opaque_credential` and `opaque_server_setup` (per-tenant OPRF
  seed and AKE keypair, AES-256-GCM at rest); drops `srp_credential`.
- `opaque_login_start` and `opaque_register_start` benchmark scenarios. The
  second is new in kind: SRP enrolment cost the server nothing, whereas
  `register/start` is unauthenticated by necessity and needs its own budget.

### Changed

- Clear the last three CodeQL alerts, and prove the Go exception
- Mint test keys and passwords per run instead of hard-coding them
- Correct comments that still described the new columns as SRP
- Rewrite CONTRACT §23 from SRP-6a to OPAQUE (contract 1.26)
- Design document, conformance fixtures, benchmarks and runbook
- **BREAKING: replaced SRP-6a with OPAQUE (RFC 9807).** SRP is removed
  entirely — endpoints, domain model, storage, SDK surface and fixtures.
  Nothing migrates and nothing needs to: an SRP verifier cannot be converted
  into an OPAQUE record (both are sealed against a plaintext the server has
  never had), and AXIAM is unreleased.
  - `srp_mode`/`srp_group`/`srp_kdf` become
    `opaque_mode`/`opaque_suite`/`opaque_ksf`, keeping the org-baseline plus
    tenant-tighten-only shape and the `disabled` default.
  - `POST /auth/srp/challenge` and `/auth/srp/verify` become
    `POST /auth/opaque/login/start` and `/auth/opaque/login/finish`, joined by
    `POST /auth/opaque/register/start` — OPAQUE needs a server round trip for
    the OPRF, which a client-side SRP verifier did not.
  - `AXIAM__AUTH__SRP_SESSION_KEY` becomes `AXIAM__AUTH__OPAQUE_SESSION_KEY`
    **and** `AXIAM__AUTH__OPAQUE_SETUP_KEY`, split by what rotating them costs.

### Removed

- `server_proof` from the login response. RFC 9807's AKE authenticates the
  server during the handshake, so the client-side `M2` check that CONTRACT
  §23.3 rule 6 had to mandate in capitals no longer exists to be forgotten.
- Verifier invalidation on username change. OPAQUE binds to a random
  server-chosen credential identifier, so a rename is free.
- The account username from `GET /auth/reset/context`, which disclosed it only
  because SRP bound its key derivation to it.
- `pbkdf2_sha256` as a KSF option, and CONTRACT 1.25's errata about the four
  SDKs that could not compute Argon2id. One shared core makes it universal; the
  weaker rung is now scrypt, which is memory-hard.
- `num-bigint` and `num-traits` from `axiam-auth`, whose only consumer was
  SRP's modular exponentiation.

### Fixed

- Route every long-lived secret through the provider
- Place axiam-opaque-wasm in the crate-layering table
- A malformed OPAQUE message from a client returned `500`. Client-supplied
  input (`400`) is now separated from corrupt stored state (`500`) by
  `AuthError::OpaqueMalformed` and distinct hex decoders.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Cover the untested pure-logic seams in axiam-core (#345)

## [1.0.0-alpha30] - 2026-08-20

### Fixed

- Bump axiam-sdk-wasm/Cargo.toml with the rest of the rust SDK

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP login, enrolment on password change and reset
- CONTRACT.md §23, cross-language SRP vectors, OpenAPI, docs
- SRP challenge/verify endpoints, enrolment and bootstrap support
- SRP-6a core, domain model and org/tenant policy

### Changed

- Generate the frontend tests' password and refusal fixtures
- Give the 4096-bit group check a timeout that fits its cost
- Generate the enrolment salts in the REST tests
- Generate the auth crate's test key, salt and x
- Mint the login test's credentials per run
- §23.3 rule 4 errata and the §23.8 table, at contract 1.25
- Record the two SRP handler modules in the frontend coverage matrix
- Add srp_challenge scenario and register it in the harness

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Enforce the advisory ignore-list invariant instead of asserting it
- Patch h2 0.4 and document why 0.3 must be ignored
- Split AppState into seven cohesive sub-states (F3)
- Name the CI job correctly in the layering docs
- Enforce missing_docs, starting with axiam-authz (F6)
- AccessTokenSpec — one description, one signer (F4)
- One definition of a UNIQUE violation, and a gate (F5)
- Gate the crate dependency graph on pointing inward (F1)
- SOLID / clean-code / clean-architecture review of AXIAM + 11 SDKs
- Bump the minor-patch group with 4 updates
- Bump actions/upload-artifact from 4.6.2 to 7.0.1
- Bump taiki-e/install-action from 2.85.10 to 2.85.13
- Bump github/codeql-action/upload-sarif
- Bump the minor-patch group in /frontend with 5 updates
- Re-trigger CI after the 2026-08-17 GitHub outage
- Bump postcss

### Fixed

- Keep the /oauth2/jwks description byte-stable across F3
- Route every page error through getApiErrorMessage (F8)
- Thread the hash gate into the client-gated auth test
- Use numeric UIDs in USER directives (DL3066)
- Separate expected-throttle cells from genuine failures
- Gate ValidateCredentials' Argon2id verify (B1)

## [1.0.0-alpha27] - 2026-08-17

### Added

- AMQP is TLS-only, server side and in every stack
- Long-lived provisioning tokens, and two SCIM setup traps closed
- Close the residual admin-interface gaps before beta
- Nested-resource authorization depth sweep (N1)
- Nested-resource authorization depth benchmark — `just bench-nested` (N1)

### Changed

- §8b rules 7 and 8, and a gate that checks them (contract 1.23)
- Cover SAML claim extraction and attribute mapping
- Cover the WebAuthn state-token machinery and the SAML bearer-confirmation checks
- §22.14 declarative reactor handler binding (contract 1.22)
- Regenerate openapi.json for the SCIM token endpoints
- Cover the SCIM and MDS error taxonomies, and the token-exchange refusal codes
- **`AppState` split into seven cohesive sub-states (F3).** The REST
  composition root carried **75 public fields**, nearly all concrete
  `Surreal*Repository<C>` values, and every handler received all of them.
  A scan found that **46 of the 75 are referenced by exactly one handler module
  each**; those move into `PkiState`, `WebauthnState`, `GdprState`,
  `MailState`, `EventsState`, `OAuth2State` and `FederationState`, taking the
  root from 75 members to 36.

  **This is a field-grouping change, not a dispatch change.** Boxing the
  repositories behind `Arc<dyn …>` would have collapsed the `C` parameter too,
  and would have put vtable dispatch on the authorization hot path — what a
  service mesh calls on every request — for a cosmetic gain. Every type,
  monomorphisation and generated instruction is what it was; what changes is
  who can see what.

  `state.rs` becomes `state/mod.rs` + `state/bundles.rs`. Migration was
  mechanical and compiler-verified: `state.foo` → `state.<bundle>.foo` at 131
  call sites across 19 files. No handler logic, route, wire format or test
  expectation changed. Rationale in `claude_dev/appstate-substates.md`.

- **Documentation is enforced, one crate at a time (F6).**
  `[workspace.lints.rust] missing_docs = "warn"` now exists and `axiam-authz`
  opts into it, with its ten undocumented items written up. The lint is a
  warning locally and an error in CI (clippy runs `-D warnings`), so a local
  `cargo check` does not fail mid-thought while a pull request cannot merge
  without the sentence.

  Measured, so the next step can be planned rather than discovered:
  **`axiam-core` has 993 sites**. `missing_docs` fires on struct and enum
  *fields*, not only the items containing them, so that is roughly four times
  the number of public types. It is deliberately left for its own change —
  993 doc comments written in a hurry to clear a lint are 993 sentences nobody
  will trust.

- **`AccessTokenSpec`: one description of a token, one signer (F4).** Access-token
  issuance had grown into twelve public functions in three telescoping chains,
  each tier existing only to add one parameter to the tier below
  (`issue_access_token` -> `_bound` adds `cnf` -> `_enriched` adds `ext`). Five
  carried `#[allow(clippy::too_many_arguments)]`; `issue_id_token` takes ten
  positional parameters. Adding one claim meant adding one function per chain,
  so a module whose entire job is "describe a token and sign it" was closed to
  extension — and the signing tail was copied six times, which meant "AXIAM
  signs with EdDSA" could have changed in five of them.

  `AccessTokenSpec` describes a token once; `sign_claims` signs it once. The
  four constructors (`user`, `oauth2_client`, `service_account`, `exchanged`)
  each stamp the `aud`/`sub_kind` pairing that belongs to that principal, which
  is what §4.3 / SEC-006 route narrowing reads and what §17.2 residual 1 was a
  case of getting out of step.

  **All twelve names keep their signatures** as thin delegations, so no caller
  changes. Token bytes, claim order, `jti` policy and every default are
  unchanged, which is what the pre-existing token suites assert. Rationale in
  `claude_dev/token-issuance-spec.md`.

- **UNIQUE-violation detection lives in one place, and CI now says so (F5).**
  Deciding "was this a conflict?" means matching substrings in a SurrealDB
  error message, and that match is a security outcome: at the three replay
  guards it is the difference between refusing a replayed SAML assertion, AMQP
  nonce or DPoP proof and accepting it as fresh. `classify_write_error` had
  documented itself as the only place allowed to do it since D-09; five call
  sites carried their own copy of the marker set anyway, each with a comment
  pointing at one of the others.

  The markers now live once in `axiam_db::helpers`, behind `is_unique_violation`
  and three classifiers (`classify_replay_write_error`,
  `classify_conflict_write_error`, `classify_write_error`), and
  `scripts/check-conflict-markers.py` fails the build if a sixth inline copy
  appears. The three replay tables also share one `cleanup_expired_rows` sweep
  instead of a byte-identical copy each. No behaviour changes: the marker set,
  the fallthrough to 5xx, and every error variant are what they were.

- **BREAKING: AMQP is TLS-only.** `AXIAM__AMQP__URL` must be `amqps://`; every
  other scheme is refused before a socket is opened, in a debug build exactly
  as in a release one. `AXIAM__AMQP__ALLOW_PLAINTEXT` is **removed** — it is no
  longer read, and `scripts/check-amqp-transport.py` reports it as a stale
  leftover wherever it survives. The default `AXIAM__AMQP__URL` changes from
  `amqp://localhost:5672` to `amqps://localhost:5671`.

  The flag did what an escape hatch does. Four stacks reached for it — dev
  compose, the e2e stack, the benchmark target and CI — each with a sound local
  argument (throwaway data, an ephemeral broker carrying synthetic fixtures, a
  hop the harness is trying to measure rather than encrypt). The aggregate was
  that "AMQP is TLS-only" described the production compose file and the k8s
  manifests, and nothing else this repository runs. Broker traffic carries
  authorization requests, audit events and mail payloads across service
  boundaries, and HMAC signing (§8) gives those authenticity and replay
  protection but not confidentiality.

  **To upgrade:** point `AXIAM__AMQP__URL` at your broker's TLS listener and,
  for a privately-issued broker certificate, set
  `AXIAM__AMQP__TLS__CA_CERT_PATH`. `scripts/gen-broker-tls.sh` mints a CA and
  broker certificate if you have no PKI to hand; `just dev-up` and
  `just bench-up` now call it for you. There is still deliberately no
  verification-skip option.

- All four remaining plaintext stacks moved to an AMQPS broker: dev compose,
  the e2e stack, the benchmark target, and CI's test/coverage jobs. CI starts
  RabbitMQ with `docker run` rather than as a `services:` container, because a
  service container starts before any step could mint the certificate it would
  need to mount.

- **Benchmark comparability:** the AXIAM target's broker hop was plaintext
  through run 5 and is now TLS. AMQP-carrying figures (async authz, audit
  ingestion) are not directly comparable across this change, and the Keycloak
  comparison target is unaffected by it. Re-baseline rather than extending a
  trend line through it.

### Fixed

- Install the rustls CryptoProvider before dialling amqps://
- The listener assertion had its own fields backwards
- Assert the AMQPS listener bound, and bound the test that needs it
- The broker's TLS config was never valid Erlang args
- Copy the broker's TLS material in rather than bind-mounting it
- Configure the AMQPS broker with a file, not mangled erl args
- Stop error messages from rendering credentials
- Construct AppState with scim_token_repo, and record the new surface
- Define the scim_token table instead of relying on implicit creation

### Security

- **`h2` bumped to 0.4.16, and RUSTSEC-2026-0258 ignored for the copy that has
  no fix** (h2 queues empty DATA frames without limit — unbounded memory, or a
  panic on length overflow; upstream severity low).

  Two copies of `h2` resolve. The **0.4.x copy (reqwest / tonic / hyper) is
  patched**: `Cargo.lock` moves 0.4.15 → 0.4.16, a lockfile-only change with 91
  dependencies unchanged. The **0.3.27 copy cannot be**: it arrives via
  `actix-http` ← `actix-web` / `actix-governor`, the advisory patches `>=0.4.16`
  only with no 0.3.x backport, and `actix-http` 3.13.3 / `actix-web` 4.14.1 —
  both released 2026-08-09 — are the newest versions and predate the 2026-08-17
  advisory. There is nothing upstream to take.

  **That copy is the one serving the REST listener, so this suppression covers a
  reachable advisory** — unlike every other entry in the ignore list, which are
  never compiled, off by default, or off the reachable path. `tls.rs` advertises
  `h2` in ALPN and refuses to start rather than let ALPN be narrowed to
  HTTP/1.1. Neither the `server.h2` window knobs nor a stream cap bound it
  (empty DATA frames consume no flow-control credit, and `actix-http` never
  sends `SETTINGS_MAX_CONCURRENT_STREAMS`). It is availability-only — no key,
  token or data compromise — and an operator who needs the exposure gone before
  actix ships a fix can terminate TLS at an edge that does not offer HTTP/2
  (`docs/security-profiles.md`, `benchmarks/targets/axiam/tls/tls13-h1.conf`).

  The entry carries that reasoning in full in `deny.toml`, and is to be dropped
  the moment `actix-http` publishes a release built on h2 0.4.

- **The advisory ignore-list is now enforced to be written consistently in both
  places** — `scripts/check-audit-ignore-sync.py`, wired into the Architecture
  Invariants job. `cargo-deny` reads `deny.toml`; `cargo-audit` reads the
  workflow's `ignore:` input and never looks at `deny.toml`, so the list exists
  twice and "keep them in sync" was a comment with nothing behind it. Drift is
  silent in both directions: an ID only in `deny.toml` leaves `cargo audit` red
  for a reason nobody wrote down, and an ID only in the workflow means the
  rationale for suppressing it is recorded in no file at all. Like the other
  gates added here, it ships a `--self-test` that runs on fixtures rather than
  on the repository it guards, and it was verified by deleting an ID from the
  workflow and confirming it names the missing one.

## [1.0.0-alpha26] - 2026-08-16

### Added

- Implement the lapin reactor transport (X1 R2.4)

### Changed

- Close the reactor transport's coverage gaps

### Fixed

- Recover the shared connection from a broker restart
- Close the neutralized-posture holes the alpha25 dry run exposed
- Activate the AXIAM bench user after seeding it

## [1.0.0-alpha25] - 2026-08-16

### Added

- A host allowlist for same-network IdPs behind the SSRF guard (SEC-107)
- Give SCIM provisioning a real bucket (R5.2 tail)
- SDK-Q10 — reason supersedes deny_reason, deprecate-and-add (R5.6)
- GRPC admin service, health surface, integration tests and docs (R2.3, R2.4, R2.6)
- Wire the reactor gate into all five interceptor sites (R2.2, X1)
- Add the axiam-scim crate — SCIM 2.0 provisioning under /scim/v2 (R3.1, B4)
- Per-client logout settings — post_logout_redirect_uris and back-channel URI (R4.2d, B5)
- Scopes CRUD and the effective-access preview with deny cascade (R4.2c, R4.2e)
- Add the device verification page and the GDPR privacy console (R4.1, R4.2a)
- Give FormDialog an accessible error slot and thread mutation errors (R4.3)
- Carry sender-constraining, UMA and X4 provenance on the gRPC surface
- X5.1 second half — private_key_jwt and DPoP (contract 1.16)
- X4 — external-IdP token exchange (RFC 8693, cross-domain)
- X3 — attestation policy enforcement via FIDO MDS3
- X2d — resource registration, RPT introspection, provenance
- X2c — the UMA 2.0 HTTP surface
- X2b — permission endpoint and uma-ticket grant
- X2a — permission ticket domain model and store
- Reactor admin console (X1)
- X1b — REST CRUD, event registry endpoint, OpenAPI
- X1a — event registry, wire protocol and dispatch chain
- §19 config_clamped event — a clamp must be reported (1.9)
- Mount RP-initiated and back-channel logout (B5b)
- Logout-token issuance and session identity for B5
- Mount PAR and teach the authorize endpoint request_uri (B5)
- PAR core — request-URI issuance and single-use consumption (B5)
- Finish the token-exchange grant and wire B2/B3 into the server (B3)
- Wire the token-exchange grant into the REST surface (B3, WIP)
- Token-exchange core — the narrowing rules and their property test (B3, WIP)
- Mount the Device Authorization Grant's REST surface (B2)
- The three unblocked new-feature cells, and why the rest wait (E4)
- Bulk-seed tooling for the seed-size sensitivity cell (E3/J12)
- Device authorization grant — core, storage and state machine (B2, partial)
- A11y smoke suite, coverage matrix, and the deny-effect editor (C3, C4)
- Passkey and security-key enrolment and sign-in (C1, C2)
- RBAC deny-override — explicit deny that beats every allow (B1)
- TLS transport encryption for broker traffic (A6)
- Opt-in strict session-revocation mode + document the default (A4/J10)
- Read-replica routing primitive + staleness contract (A3/J11)
- Link the Coveralls coverage reports
- **WebAuthn attestation policy enforcement (X3).** Registration has always
  accepted any authenticator; tenants can now opt into "only FIDO-certified /
  non-revoked / explicitly-allowed authenticators may register," backed by
  the FIDO Alliance's Metadata Service (MDS3).

  `axiam-pki` gains an MDS3 ingestion pipeline: fetch (or load, air-gapped)
  the ~10 MB signed BLOB, verify its RS256 JWT signature chain against a
  **digest-pinned** vendored GlobalSign Root CA – R3 anchor — matching the
  pinned SHA-256 is the check, the anchor is never re-fetched at runtime —
  pin the leaf's SAN DNS identity (chaining to a public CA root by itself
  only proves "some GlobalSign EV customer," not "FIDO Alliance"), require
  every issuer in the chain to actually be a CA (closing an end-entity
  certificate splice a naive verifier would miss), reject a rollback to an
  older BLOB serial, and mark a BLOB stale past its own `nextUpdate` without
  ever hard-failing ingestion over it. Ingestion is opt-in
  (`AXIAM__PKI__MDS_ENABLED=false` by default — zero outbound calls) with a
  weekly background refresh, an admin-triggered `POST /api/v1/mds/refresh`,
  status via `GET /api/v1/mds/status`, and an `AXIAM__PKI__MDS_BLOB_PATH`
  escape hatch for air-gapped deployments (the BLOB itself is not vendored in
  git).

  Per-tenant policy (`GET|PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`)
  controls attestation mode, required certification level, AAGUID
  allow/block lists, and revoked-status blocking, evaluated by a pure,
  exhaustively-tested decision function
  (`axiam_core::models::webauthn_policy::evaluate`): blocklist beats
  allowlist, compromise/revocation status is sticky across the authenticator's
  whole history, and an AAGUID explicitly allow-listed by an admin is trusted
  even with no MDS entry for it. The default (`mode: none`) reproduces
  today's behavior byte-for-byte, with no MDS lookup at all.

  **Every non-`none` mode excludes synced passkeys** (iCloud Keychain, Google
  Password Manager) **and hybrid sign-in**, not only the strictest setting —
  `webauthn-rs` always requires user verification and always rejects
  synchronised authenticators once attestation is requested at all. AXIAM's
  `mode: indirect` still requests `direct` conveyance on the wire; it differs
  from `mode: direct_required` only in policy strictness afterwards. See
  [`docs/admin/authenticator-policies.md`](docs/admin/authenticator-policies.md)
  for the full trade-off before enabling it.

  Denials return a fixed, non-specific error and audit
  `webauthn.attestation_denied` with the AAGUID and machine-readable reason —
  never a raw library error to the end user. **Existing credentials are never
  auto-revoked** on a policy change: `GET
  /api/v1/tenants/{tenant_id}/webauthn/compliance-report` lists which
  registered credentials would now fail the current policy (a credential
  with no recorded AAGUID — every credential registered before X3 — is
  reported `unknown`, never as a violation), and revocation stays the
  existing admin credential-delete path, a deliberate human action.

  Known, documented limitation: `block_revoked_status` covers `REVOKED` and
  the three `*_COMPROMISE` statuses, not `USER_VERIFICATION_BYPASS` — an
  authenticator with only a UV-bypass advisory still passes that check.
  Operators who care should use `blocked_aaguids`.

- **SCIM 2.0 provisioning (RFC 7643/7644, B4).** A new `axiam-scim` crate mounts
  `/scim/v2`, so an IdP — Okta and Microsoft Entra are the two the scope was
  drawn from — can create, update, deactivate and delete users and groups in a
  tenant without anyone writing a bespoke sync job against `/api/v1`.

  `Users` and `Groups` get full CRUD plus the discovery endpoints
  (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`). It maps onto the
  **existing** `UserRepository`/`GroupRepository` — there is no parallel SCIM
  store, so a SCIM-provisioned user is an ordinary AXIAM user from the first
  request onward.

  The scope is deliberately the subset those two IdPs actually send, and the
  parts outside it fail loudly rather than silently doing something
  approximate: `PATCH` implements the RFC 7644 §3.5.2 add/replace/remove ops on
  standard attribute paths; filtering is `userName eq` and `externalId eq` with
  paging, and any more complex filter returns **400 `invalidFilter`**; bulk
  operations are not implemented and `POST /Bulk` returns **501**.

  Authorization is a dedicated `scim:provision` permission, checked per request.
  Tenant scoping is not a check SCIM adds but a channel it never opens: the
  tenant comes only from the validated JWT's `tenant_id` claim, never from the
  request path or body, and every repository call takes that tenant as a
  mandatory parameter. The contract tests exercise that adversarially — by UUID,
  cross-tenant, on GET/PUT/PATCH/DELETE/list — rather than only testing "no
  token".

  **Operator note:** the bearer principal must be a tenant *user* that holds
  `scim:provision` (create a `scim-provisioner` user and grant it a role through
  the existing `/api/v1` APIs), **not** a `service_account`. AXIAM's RBAC
  role-assignment edge is hard-scoped to the `user` table today, so a
  `service_account` subject can hold no RBAC permission at all. That predates
  this crate. See [`docs/api/scim-provisioning.md`](docs/api/scim-provisioning.md)
  for the Okta and Entra walkthroughs.

  Rate limiting: one bucket spans the whole `/scim/v2` scope — reads, writes and
  discovery alike — at `scim_per_min = 600` (`AXIAM__RATE_LIMIT__SCIM_PER_MIN`),
  the same 10/s the gRPC Admin family uses. Both surfaces are fully-privileged,
  machine-driven, and sized as a CPU guard on Argon2id, which is SCIM's real
  cost profile: `POST /Users` and a `password` PATCH both hash. The limiters sit
  *outside* the credential check so an unauthenticated flood is shed before it
  reaches Argon2id, which is also why the discovery endpoints share the bucket
  instead of going unmetered.

- **OIDC logout: RP-initiated and back-channel (B5).**
  `GET`/`POST /oauth2/end_session` ends the session named by a signed
  `id_token_hint`, and every client that participated in that session and
  registered a `backchannel_logout_uri` is POSTed a signed logout token.
  Advertised in discovery as `end_session_endpoint`,
  `backchannel_logout_supported` and `backchannel_logout_session_supported`.

  Both halves operate on a **session**, not a user: a user with a phone and a
  laptop who logs out on the laptop keeps the phone signed in. ID tokens now
  carry `sid`, and it survives refresh-token rotation so an RP that stored it
  at login can still match a logout token to its own session.

  The endpoint is unauthenticated by necessity — a user whose session already
  expired must still be able to complete a logout — so what identifies the
  target is the *signature* on the hint. Expiry on the hint is deliberately
  not checked (a logging-out user's ID token has usually expired already); the
  signature is. An unverifiable hint ends **nothing**: there is no fallback to
  "end every session for the named subject", which would be a
  denial-of-service primitive for anyone who knows a user id.

  `post_logout_redirect_uri` is honoured only on **exact match** against the
  client's new `post_logout_redirect_uris` allow-list — a separate list from
  `redirect_uris`, because one receives authorization codes and the other
  receives a browser after logout. A non-matching URI still logs the user out
  and renders AXIAM's own page: refusing to log someone out because their RP
  sent a bad parameter is the wrong failure.

  Logout tokens carry the mandatory `events` member, always name `sid`, live
  120 s, and can never carry `nonce` (the issuer takes no such parameter, so
  it cannot emit one by accident — its presence is how an ID token gets
  replayed as a logout token). Delivery is best-effort with a bounded retry
  and never blocks the logout.

  New: `AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` (30). See
  [`docs/api/logout.md`](docs/api/logout.md) and CONTRACT.md §12.7.

- **Pushed Authorization Requests (RFC 9126, B5).** `POST /oauth2/par` accepts
  an authorization request over a direct, client-authenticated POST and returns
  an opaque single-use `request_uri` to put in the browser redirect instead of
  the parameters. `/oauth2/authorize` accepts it, refuses to mix it with inline
  parameters (where parameter confusion lives), and a client registered
  `require_par` may not send its parameters through the browser at all. New:
  `AXIAM__RATE_LIMIT__PAR_PER_MIN` (120). Required by FAPI 2.0.

- **OAuth2 Token Exchange (RFC 8693, B3).** A service holding a user's access
  token can exchange it for a *narrower* one —
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on
  `POST /oauth2/token`, advertised in OIDC discovery. Previously a mesh caller
  had two options, both wrong: forward the user's token verbatim
  (over-privileged, and the second hop cannot tell the caller from the user)
  or use its own service credentials (right privileges, no user context).

  One rule governs the feature: **an exchange may only ever narrow.** No
  parameter, configuration or client grant makes the issued token permit
  something the subject token did not already permit. Concretely:

  - `granted = requested ∩ subject_scopes ∩ client_allowed_scopes`. A
    requested scope the subject does not hold is **refused** (`invalid_scope`),
    not silently dropped — silent narrowing produces a token that works for
    some calls and not others, and the caller finds out at the *next* service.
    The client's own registration bounds the result even when the subject token
    is broader, which is what stops a compromised low-privilege service holding
    an admin's token from minting an admin token.
  - `exp = now + min(subject_remaining, max_exchange_lifetime)`. The exchanged
    token never outlives its subject, so an exchange cannot launder lifetime.
    For the same reason **no refresh token is issued** — one would defeat the
    cap outright — and naming `requested_token_type=…:refresh_token` is
    refused rather than answered with an access token.
  - `audience`/`resource` must be registered to the exchanging client; an
    unconstrained `aud` is the mesh equivalent of an open redirect.

  **Delegation vs impersonation** is selected by the presence of `actor_token`,
  and the two are not equally available. Delegation adds an `act` claim naming
  the actor (nested on re-exchange, capped at depth 3 so a signed token cannot
  grow an unbounded field). Impersonation issues a token indistinguishable from
  one the user obtained directly, so it is **off by default** — a client needs
  the explicit `urn:axiam:params:oauth:grant-type:may-impersonate` grant, and
  one without it is refused (`unauthorized_client`) rather than quietly
  downgraded to delegation. Every exchange is audited with client, subject,
  actor, kind, requested and granted scopes, audience and outcome; for
  impersonation that record is the *only* evidence the acting party was not the
  subject.

  v1 accepts AXIAM-issued subject tokens only — accepting another IdP's token
  means accepting whatever it asserts about the subject, and the trust
  configuration that makes that safe is its own feature (X4). A cross-tenant
  subject token answers `invalid_grant` rather than a distinct error, because
  learning a token is valid *somewhere else* is a tenant-enumeration signal.

  New rate-limit bucket `AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN` (120): an
  exchange verifies an inbound JWT, reads the client registration and writes an
  audit record, and it is what an attacker holding one stolen token would
  hammer looking for a widening path. See
  [`docs/api/token-exchange.md`](docs/api/token-exchange.md).

- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- **Passkeys and security keys in the admin UI.** The server had shipped the
  full WebAuthn registration and authentication ceremonies for releases, but
  the frontend had zero WebAuthn references — the MFA page advertised passkeys
  as "Coming soon" and the login page could not exercise them. Both are now
  wired: enrol a platform passkey or a cross-platform security key from
  Profile → MFA methods, and sign in with a passkey via browser autofill
  (conditional mediation), an explicit button, or as a second factor. The MFA
  list distinguishes `Passkey` from `Security key` rather than labelling both
  "WebAuthn". All ceremony policy stays server-side.
- **Deny-effect selector in the role editor**, with a distinct `DENY` badge on
  granted permissions. Deny rules were creatable over the API from the moment
  B1 landed and invisible in the console — the worst of both worlds.
- **Frontend coverage matrix** (`claude_dev/frontend-coverage-matrix.md`) plus
  a CI check that fails when a REST handler module has no row, so a new server
  surface cannot ship without someone recording whether it needs a UI.
- **axe-core accessibility smoke suite** over the main pages and the
  design-system components the audit fixed, wired into the fast frontend CI job.
- **RBAC deny-override (explicit deny).** A role→permission grant now carries
  `effect: "allow" | "deny"`, defaulting to `"allow"`. A deny grant overrides
  **every** allow, at any depth of the resource hierarchy and at equal
  specificity — deny-override, not most-specific-wins. Closes SEC-040 and the
  "no explicit deny" entry in the comparison page's cons list. Check responses
  gain `reason_code` (`allowed` | `no_grant` | `denied_by_rule`) so a caller
  can tell "ask an admin for access" apart from "an admin has already
  decided". Fully backward compatible: existing grants and `effect`-less
  requests both mean allow, and no migration is required beyond the additive
  schema field.

- **AMQP transport encryption (`amqps://`).** Broker traffic was plaintext in
  every deployment artifact. `AmqpConfig` now accepts `amqps://` URLs with an
  optional TLS block (custom CA bundle, optional client certificate for mutual
  TLS toward the broker), and the prod compose stack and k8s manifests speak
  TLS 1.3 on port 5671 with the plaintext listener switched off. There is
  deliberately no verification-skip option: `ca_cert_path` covers the
  legitimate reason to want one. HMAC signing stays mandatory — TLS is
  confidentiality in transit, HMAC is end-to-end authenticity across broker
  hops, and neither substitutes for the other. SDK contract §8b.
- **gRPC strict session-revocation mode** (`AXIAM__GRPC__STRICT_REVOCATION`).
  Opt-in per-request revocation enforcement on the gRPC data plane, matching
  REST. See "Changed" for the default this makes explicit.
- **Read-replica routing primitive** (`AXIAM__DB__READ_REPLICAS`, off by
  default) with a documented staleness contract; authorization, identity and
  JWKS reads are replica-eligible, session revocation and write-path reads are
  pinned to the primary and cannot be configured otherwise.
- Rate-limit scenarios for the three limiter families that had none (`revoke`,
  gRPC admin, gRPC infra), so all eight families appear in the enforcement
  verdict table.

### Changed

- Quick-run benchmark runbook for alpha25 (AXIAM-only, p0/p2/p3)
- Execution log update 5b — SEC-096..SEC-107, and a runbook row the fix invalidated
- Contract 1.20 and the SEC-096..SEC-107 dispositions
- Correct the CA-trust claim and the nonce backstop's reach (SEC-105, SEC-106)
- Execution log update 5 — the tracked follow-ups
- Make the frontend job print the coverage it achieved
- Provision the scim:provision principal the SCIM scenario needs
- Detect stale vendored artifacts across the SDK repos (R5.8b)
- Execution log update 4 — R5.8 fan-out, merges, R5.9, R5.2 tail
- Ratchet the Rust line-coverage floor 80 -> 88 (R5.9)
- The two authored k6 scenarios are no longer owed (R5.11)
- Execution log update 2 — final wave status, residuals and new findings
- Add the first coverage floor to vitest.config.ts (R5.9)
- F4-bis review of everything post-2026-08-10 (R6)
- Drop the on-failure server-log dump entirely (R5.1)
- Shrink the smoke failure dump to 40 lines (R5.1)
- Clear the two clippy findings in the reactor test code (R2.2)
- Rustfmt the gate wiring and drop a literal test credential (R2.2)
- Prove X4 token exchange against a real Keycloak (R5.4)
- Close the X2 test gaps — Keycloak RPT compat and a deny-override property test (R5.3)
- Supply the three mandatory startup secrets to the smoke stack (R5.1)
- Assert native constraint validation on the login form (R4.7)
- Make the runtime-smoke failure legible and supply b3's password (R5.1)
- Drop needless borrows in the contract tests (R3.1)
- Join the grants_by_role declaration onto one line (R1.3)
- Add the F3 examples tree with a two-tier CI smoke job (R5.1)
- State the SEC-089 audience allow-list where operators and callers read it (R1.1)
- Refresh the frontend coverage matrix for the R4 surfaces
- Add the execution log for the 2026-08-15 remediation pass
- Add §22 Reactors and bump the contract to 1.18 (R2.1)
- Record token exchange's revocation posture where F4 asked for it (R1.2)
- Add A1's owed sustained-flood integration test (R5.2)
- Run the limiter suite as a dedicated job (R5.2)
- Add the missing flood scenarios and the two unwritten R7 cells (R5.2, R7)
- Correct the stale permissions row in the coverage matrix (R4.9)
- Emit CycloneDX SBOMs for the Rust workspace and frontend (R5.10)
- Truth up stale status lines across five planning docs (R5.11)
- Benchmark Run5 changes
- Consolidated remediation plan from the 2026-08-15 full verification
- Drop the owned copies totp-rs 5.x's Secret::Encoded required
- Keep the RFC 9449 `ath` vector in exactly one place
- Regenerate openapi.json for the contract 1.16 client fields
- Bump totp-rs from 5.7.2 to 6.0.0
- X5 — FAPI 2.0 readiness, conformance harness, and contract 1.15 (#319)
- Contract 1.14 + STRIDE model for the X6 single-use guarantee
- Subject_token_type becomes required (contract 1.13)
- Add X6 — make single-use redemption a guarantee (closes the #302 residual)
- Bump the minor-patch group across 1 directory with 7 updates
- Allow BSL-1.0 for xxhash-rust
- Dispatch /oauth2 errors on the error field (contract 1.12)
- Lift the §12.6 Swift/C/C++ deferral (contract 1.11)
- §20 — the UMA 2.0 contract the SDK fan-out implements
- Shrink test-job target/ so the gRPC relinks stop exhausting runner disk
- Bump Swatinem/rust-cache from 2.9.1 to 2.9.2
- Bump dtolnay/rust-toolchain
- Bump github/codeql-action/upload-sarif
- Bump taiki-e/install-action from 2.85.5 to 2.85.10
- Bump the minor-patch group in /frontend with 6 updates
- Bump actions/attest-build-provenance from 4.1.1 to 4.2.2
- Fold the single-use suite into one test binary
- E2e specs for the reactor console (X1)
- Record the reactor console as a P1 gap (X1)
- Correct the deny-override claim across the live doc set (F2) (#288)
- F4 review of the B-track; fix SEC-088 sub_kind confusion
- §16 preamble rewritten from tests, not greps (1.8.3)
- §16 preamble errata — five SDKs diverged (1.8.2)
- §16 preamble errata — three SDKs diverged, not two (1.8.1)
- Contract 1.8 — retry policy, decision memo, close(), telemetry (D5) (#283)
- Contract 1.7 — device_login credential-adoption errata (D6)
- Contract §12.7 logout helpers; server logout guide (D4)
- Contract §14 device grant, §15 token exchange; B5 design (D4)
- Drive the device-flow suite green — all 14 pass
- Answer the two questions that decide X3's cost, before starting it
- One shared test-password helper; lint the AMQP transport posture
- Add extra B-track features doc (X1-X5) — Reactors, UMA 2.0, MDS3, external-IdP exchange, FAPI 2.0
- Cut refresh rotation from five datastore round trips to three (A2/J2)
- Add A6 — AMQP transport encryption (amqps/TLS)
- Post-run-5 improvement plan — fixes, competitor gaps, frontend/SDK completion
- Update benchmarks page to run 5, add SDK and §10 sections
- Benchmark run 5 — release image, full matrix, three mysteries closed (#275)
- Run 5 targets the published 1.0.0-alpha24 image, not a local build
- **BREAKING (release builds): a plaintext `amqp://` broker URL is now
  refused** unless `AXIAM__AMQP__ALLOW_PLAINTEXT=true`. Mirrors the existing
  fail-closed posture for the AMQP signing key. Debug builds are unaffected,
  so `cargo test` and `cargo run` keep working untouched — but note that the
  dev, e2e and benchmark compose stacks all run the *published release image*
  and so are subject to the guard like any deployment. All three now set
  `AXIAM__AMQP__ALLOW_PLAINTEXT=true` explicitly, each with a comment stating
  why plaintext is acceptable for that stack. Any other release-image stack
  with an `amqp://` URL must do the same or move to `amqps://`; it will
  otherwise refuse to start, by design.
- **Rate limiting: enforcement now matches configuration in both directions.**
  gRPC families were admitting 1/20–1/33 of their configured ceiling under a
  single-IP flood (the shared 60-second pre-check was charging requests the
  per-second governor then rejected), while REST machine endpoints
  over-admitted by up to +50% (fixed-window boundary doubling). The shared
  counter now uses a sliding window, counts admitted capacity rather than
  arrivals, and refunds downstream rejections; a newly seen key gets its
  pro-rata share of the window plus an explicit, documented 10% burst
  allowance — except below 20/min (every human endpoint, no machine one),
  where smoothing a five-request budget would cost a legitimate first-time
  user a whole request for no security benefit. Rollback:
  `AXIAM__RATE_LIMIT__SHARED_WINDOW=fixed`.
- **Refresh rotation is three datastore round trips instead of five**, via an
  atomic `consume_by_token_hash` (which also removes the read-then-delete
  window rather than tolerating it) and a TTL cache for the per-refresh tenant
  lookup. Single-use rotation, the user-status check, and consuming expired
  tokens are all unchanged.
- **Documented: gRPC does not check session revocation by default.** A user
  who logs out keeps passing gRPC authorization until their access token
  expires (up to 15 minutes). This was always true; it is now written down,
  and `AXIAM__GRPC__STRICT_REVOCATION=true` changes it.
- **gRPC `CheckAccessRequest.subject_id` is now optional**, the way the REST
  check body's has always been: an **empty** value means "the subject in the
  verified token" instead of being refused as a malformed UUID. A non-empty
  value must still equal the token's subject — gRPC has no `authz:check_as`
  cross-subject form. Empty carries the meaning rather than the field becoming
  proto3 `optional`, because that is a cardinality change `buf breaking`
  refuses. Purely a widening: every request that worked before still works.

### Deprecated

- **gRPC `CheckAccessResponse.deny_reason` — superseded by `reason`, removed at
  2.0.** The REST decision body has always called the human-readable reason
  `reason`; the gRPC one called the identical string `deny_reason`, so every SDK
  speaking both transports reconciled the two names itself, and not all of them
  reconciled them the same way (SDK-Q10). `CheckAccessResponse` now carries
  **`reason` (field 4)** with explicit presence — absent on an allow, present on
  every refusal, exactly the REST shape — and `deny_reason` is marked
  `[deprecated = true]` while continuing to carry the identical string.

  Nothing breaks today: both fields ship until **AXIAM 2.0**, where
  `deny_reason` is removed. Renaming it now would have broken every deployed
  gRPC client on the wire for no behavioural gain. Clients should read `reason`
  and fall back to `deny_reason` only when `reason` is absent *on a refusal*,
  which means the server predates this change. The rule, and the SDK-side
  obligations that go with it, are in `sdks/CONTRACT.md` §11.2 rule 9
  ("Amended 2026-08 (SDK-Q10)", contract 1.19).

### Fixed

- Normalize extension-less --scenario; read matrix trees in rl-prod-check
- Delete must report NotFound for a foreign or unknown id (SEC-104)
- Deprovisioning must revoke live sessions and refresh tokens (SEC-098)
- Correct the gate's deny paths and refuse an undispatchable registration (SEC-099, SEC-100, SEC-101)
- Stop token exchange stripping sender-constraining (SEC-096, SEC-097, SEC-102)
- B5 back-channel logout URI must be reachable from AXIAM (R5.1)
- B5 must send tenant_id on the RP-initiated logout URL (R5.1)
- Declare the containerized reactor test queue durable, not transient (R2.4)
- Close the three HIGH findings from the F4-bis review (SEC-093, SEC-094, SEC-095)
- Configure a real OIDC issuer URL for the compose stack (R5.1)
- Generate the reactor test fixture's password instead of hard-coding it (R2.3)
- B2 read tenant_id from the wrong path in the /auth/me response (R5.1)
- B2 must send tenant_id to /oauth2/device_authorization (R5.1)
- Correct the role-assignment status codes and stop carrying a literal test password (R5.1)
- B1 asserted 201 where the API returns 204 (R5.1)
- Use express-rate-limit in the B5 RP example (R5.1)
- Close the CodeQL findings in the B3 and B5 examples (R5.1)
- Allow registering the device-code and token-exchange grants
- Enforce bearer SubjectConfirmationData — Recipient, NotOnOrAfter, InResponseTo (R1.5, SEC-005)
- Key batch grants per tenant and document the widening fallback (R1.3)
- Stop claiming the RBAC engine has no deny-override (R4.4)
- Surface delete failures on the tenants page (R4.6)
- Gate every protected route and fail closed on a null /auth/me (R4.5, R4.7)
- Keep proof_replay_repo out of SamlFederationService::new
- Port TOTP to totp-rs 6.0's builder, struct Secret and Token
- The authorization-code grant joins the layered single-use mechanism
- X6 — single-use redemption becomes a guarantee (#302)
- Repair the db test build, split the frontend format helpers
- Commit the vendored MDS trust anchor, which .gitignore ate
- Give resource delete and child create a key to collide on
- Run the serialisation tests and both deployments on surrealkv
- Wire X2 into the server binary and regenerate the derived artifacts
- Stop device-grant and PAR single-use depending on conflict detection
- Decide the ticket race in `consume` instead of asking SurrealDB to
- Serialise single-use consumes for device grants and PAR
- Keep the FormDialog footer reachable on tall forms
- Register the reactor permissions and routes (X1b)
- Deny-override precedence pass — end-to-end tests + SEC-092 (#289)
- Box ClientOutcome::Found — B5's fields tripped large_enum_variant
- Classify the device verification paths; B5 registration groundwork
- Give the authorization test fixture B3's new `act` claim
- One authenticate_client, and use the J1-aware rate-limit check (B3)
- Apply SDK_BENCH_CONCURRENCY to the C++ client, not just its workers (D2/J6)
- Record the Python bench's event loop and prefer uvloop (D1/J5)
- Close the three SDK-harness audits — TS baseline, C# accounting, Rust CPU (D3/J7/J8/J8b)
- Make the required container env provable, and stop dropping investigation artifacts (E1/E2)
- Repair the two specs C1/C2 invalidated
- Set ALLOW_PLAINTEXT on the three release-image stacks A6 broke
- Generate the budget test's password; bump dev-only nanoid past GHSA-2v37-7h3g-55p8
- Exempt human-scale limits from the cold-entry seed (A1 follow-up)
- Pre-mint the refresh session pool inside the login budget (A5/J4)
- Close the two-layer starvation and boundary over-admission (A1/J1)
- Repair the dry-run matrix — teardown, seed idempotency, mTLS probe
- Realign rate-limit assertions with SEC-079; fix run-5 preflight
- Align the footer link columns

### Security

- **The authorization-code grant joins the layered single-use mechanism
  (schema v37).** `authorization_code.consume` was the fourth single-use
  consume in `axiam-db` and the only one X6 left alone — it was outside #302's
  scope. It was not broken: its redemption is a single statement, so it already
  ran in the storage engine's own transaction and two concurrent callers
  conflicted on one key. What it lacked was the second layer.

  It now carries both, identically to the other three: the guarded `UPDATE`
  inside an explicit `BEGIN`/`COMMIT`, and a per-attempt `redemption_id` read
  back in a **separate query after that transaction commits**. The read-back
  must stay outside the transaction — inside one, snapshot isolation shows
  every racer its own write and every racer believes it won.

  The reasoning is the same one that kept the nonce on the other three: a code
  redeemed twice is two token pairs from one authorization, conflict detection
  is not a documented SurrealDB guarantee, and the cost is one extra write and
  one extra read on an operation that happens once per login. A losing racer
  still answers `NotFound`, exactly as an unknown code does, so no caller can
  distinguish "someone else just redeemed this" from "no such code".

  `authorization_code_consume_serialises` now runs 50 rounds of 8 racers rather
  than one, and a new `an_authorization_code_redemption_stamps_its_nonce`
  asserts the second layer directly — a race test alone cannot tell a two-layer
  mechanism from a one-layer one when the engine arbitrates either way. Threat
  T-164 in the STRIDE model is updated accordingly.

- **Single-use redemption is now a guarantee, conditional on a persistent
  storage engine (X6, closes #302).** UMA permission tickets, RFC 8628 device
  grants and RFC 9126 PAR `request_uri`s could each admit a second concurrent
  redemption at a measured ~1 in 640 — two RPTs from one authorization
  decision, two token sets from one user approval, or a replayable
  authorization request. All three consume paths now run **two** layers rather
  than choosing between them: the guarded `UPDATE` is back inside an explicit
  transaction, so the storage engine arbitrates and aborts every loser, and the
  per-attempt redemption nonce is read back in a separate query *after* that
  transaction commits, catching any conflict the engine silently missed. The
  read-back must stay outside the transaction — inside one, snapshot isolation
  shows every racer its own write and all of them believe they won.

  A double redemption now needs two independent failures. The first layer is a
  measured property of the engine (`tools/surreal-race-probe`: zero double
  winners in 40 000 contended attempts on `surrealkv` and 9 600 on `rocksdb`,
  against 12–23 in 1 200 on the in-memory engine), so **a deployment MUST run
  `surrealkv:` or `rocksdb:` and MUST NOT run `memory:`** — see the new section
  at the top of `docs/deployment/README.md`. The shipped compose files and k8s
  StatefulSet already comply.

  `axiam-server` now attests the storage engine at startup. SurrealDB 3.2.4
  publishes no datastore identity over the wire — neither `/version`, nor
  `INFO FOR ROOT` including its `system`/`nodes`/`config` sections, nor any
  `session::*` function — so today that attestation logs a WARN saying the
  engine could not be attested. The hard guard is written and tested: when a
  SurrealDB release does expose the engine, startup refuses a `memory`
  datastore unless `AXIAM__DB__ALLOW_MEMORY_ENGINE=true`, and a unit test fails
  on the bump that makes the name available.

  The probe becomes a version-bump gate: `.github/workflows/surreal-race-probe.yml`
  re-measures `surrealkv` at 5000 × 8 in both shapes whenever `Cargo.lock` moves
  `surrealdb`, `surrealdb-core` or `surrealkv`, and fails on any double-winner
  round. Results are recorded, version-pinned, in
  `tools/surreal-race-probe/RESULTS.md`.

- **SEC-088 (fix): token exchange no longer mints a `sub_kind`/`sub` mismatch.**
  Exchanging to the machine audience rewrote `sub_kind` to `OAuth2Client` while
  leaving `sub` as the subject user's UUID — the one combination the
  `sub_kind`-tells-you-how-to-read-`sub` contract says cannot occur.
  `sub_kind` now always carries through unchanged from the subject token; the
  audience alone conveys "this token reached the M2M audience by exchange." A
  regression test exchanges a user token to `aud=axiam:m2m` and asserts
  `sub_kind == User` and `sub` unchanged.
- **SEC-089 (decision): the token-exchange audience allow-list stays
  `redirect_uris`, documented loudly instead of split into a dedicated field.**
  Adding a redirect URI to a client also authorises it as a token-exchange
  audience for that client; there is no separate audience allow-list in v1.
  This is now stated on `TokenExchangeRequest::audience`, at both allow-list
  check sites in `token_exchange.rs`, on the `redirect_uris` field docs in the
  client-management handler, in `docs/api/token-exchange.md#audience`, and in
  the generated OpenAPI schema. A dedicated `allowed_token_targets` field
  remains the intended eventual fix.
- **SEC-090 (decision): an impersonation exchange intentionally resets the
  actor-chain depth bound.** Impersonation produces a token indistinguishable
  from one the subject obtained directly, so it starts a new, unlinked chain
  rather than extending the delegation one it grew out of. No code change:
  impersonation already requires the dedicated `may-impersonate` grant, and
  the per-hop lifetime cap still bounds every chain regardless of depth.
  Recorded so the reset is not rediscovered as a surprise.
- **SEC-091 (doc): token exchange's revocation posture is now stated where an
  operator will find it.** Exchange does not consult session revocation — the
  same standing posture as non-strict access-token validation elsewhere in
  AXIAM — bounded by two properties already enforced in code: the exchanged
  token's lifetime can never exceed the subject token's remaining lifetime,
  and its granted privilege is always a subset of the subject's and the
  client's scopes. Documented in `docs/security-profiles.md` (Session-revocation
  posture) and cross-referenced from `docs/api/token-exchange.md#sec-091`.
- **SEC-092 (fix): an unrecognised permission-grant `effect` no longer reads
  back as `allow`.** `PermissionGrantRow::try_into_grant` used to default an
  unparseable `effect` to `Allow`; under deny-override that silently defeated
  every deny for the affected role during a rolling upgrade that wrote a newer
  effect value an older node could not parse. The row is now dropped instead
  — it contributes neither an allow nor a deny, decisions fall through to the
  remaining grants and ultimately to default-deny — and logged at `error`
  rather than `warn`, since reaching that branch means the datastore was
  written outside both the API validator and the schema `ASSERT`.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add the Threat Modeling & Security section
- Service-account client_credentials grant + SEC review (#267)
- Cross-replica decision-cache invalidation over RabbitMQ fanout
- Install the client-secret hasher at startup (OBS-1 fail-closed gate)
- Key client-secret hashing with the server pepper (OBS-1)
- **Service accounts can now authenticate via OAuth2 client-credentials.**
  `POST /api/v1/service-accounts` and `rotate-secret` have always returned a
  `client_secret` to the operator — but **no flow accepted it**. A service
  account's only working authentication path was mTLS
  (`POST /api/v1/auth/device`); the client-credentials grant verified against
  the `oauth2_client` table only, and nothing ever compared
  `service_account.client_secret_hash` against a presented secret.

  The grant now dispatches on the `client_id` prefix — `oa_` for `oauth2_client`,
  `sa_` for `service_account`, both server-generated and disjoint, so one lookup
  still suffices. The prefix is **not** a security decision: it only selects the
  table, and the presented secret must still verify against the row found.

  Three deliberate properties:
  - **The secret is verified before the status check**, so a caller cannot
    distinguish "exists but disabled" from "does not exist" by timing. A
    non-Active account returns the same generic `invalid_client`.
  - **No scope may be requested.** A service account registers no scopes, and
    the subset rule leaves the empty set as the only valid request; its
    authorization comes from the roles assigned to it, as on the mTLS path.
  - **The token's `sub` is the service-account id**, not the client id, and its
    `aud` is `axiam:m2m`, so §4.3/`SEC-006` route narrowing keeps it off user
    routes. A service account is now the same principal however it authenticated
    — see the breaking device-audience change below, which makes the mTLS path
    stamp `axiam:m2m` as well.

- **Legacy client-secret hashes in `service_account` are now countable
  (§15.2).** `count_legacy_secret_hashes(tenant)` plus a startup warning.
  With the grant above in place these rows now migrate lazily on first
  authentication, exactly as `oauth2_client` rows do; the count covers the case
  migration cannot reach — a service account that never authenticates — which is
  what decides whether the legacy hash arm can be retired. **Rotation** clears
  such a row.
- **CI gate: remediation evidence must resolve on `main` (§11.2).**
  `scripts/check-remediation-evidence.py` parses the remediation tables in
  `claude_dev/security-analysis-*.md` and verifies every cited commit is
  reachable from `origin/main` in the repository it claims. A recorded commit
  hash is not evidence a fix shipped — a hash exists the moment a commit is
  authored, on any branch — and this pass caught a real instance of a fix
  recorded as remediated while still unmerged. Rows that cannot be verified are
  printed individually under an explicit `SKIPPED, NOT VERIFIED` banner rather
  than passing silently.

- **`sdks/CONTRACT.md` §10.1 — minimum local-verification set (normative).**
  States once, for every SDK, what a guard must check before turning a token
  into an identity: signature with `alg` pinned before key lookup, `exp`
  REQUIRED, `nbf` honoured when present, `tenant_id` asserted against the
  configured tenant, `iss`/`aud` checked when configured, and a named bounded
  clock skew — all fail-closed. Written because `SEC-071` and `SEC-080` were the
  same defect found independently in two SDKs: each verified a different subset,
  and each subset looked complete in isolation.

### Changed

- Close the review series; make the website section handoff-ready
- Fix the §22.3 residuals (#272)
- Verify §20/§21 — every finding closed
- Bump the minor-patch group across 1 directory with 3 updates
- Record the rule-8 guardrail tests as closed (§21)
- Close SEC-086 fully and SEC-087, fix the CHANGELOG inversion (#269)
- Verify d15878a2 — device audience narrowed; SEC-086 partial, SEC-087 new
- Close SEC-086 and the §17 residuals, narrow the device audience (#268)
- Verify §16 and review the new service-account grant
- Bump pem from 3.0.6 to 4.0.0
- Bump the minor-patch group with 2 updates
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Bump github/codeql-action/upload-sarif
- Bump the minor-patch group in /frontend with 8 updates
- Bump docker/login-action from 4.5.1 to 4.6.0
- Bump hadolint/hadolint-action from 3.3.0 to 3.4.0
- Close the §15 partials and observations (#259)
- Verify §14 — SEC-085 closed, no open findings remain
- Close every open item from the 2026-08-02 security analysis (§13) (#258)
- Final verification pass — §12 claims confirmed; one new HIGH (SEC-085)
- Close §4 residual 2 — cross-replica cache invalidation shipped
- Record the CONTRACT §10.1 sweep — five new findings; correct §10.7
- Normative SDK local-verification set; close residual 10.4-3 as misdescribed
- Verify the SEC-079/080 remediation; all findings closed
- Record §10 remediation status as claims pending verification
- Independent re-verification pass; sync threat model for T-145
- Add exact-command reference to the run-5 runbook; fix three harness defects it exposed
- Generate the query-plan fixture password instead of hard-coding it
- Add run-5 runbook; add CONTRACT §13 webhook verification
- Record remediation status for SEC-071..078 and T-145
- Fix authz-path table scans, add session-validation cache and CC stage timings
- Add 2026-08-02 code-level security analysis
- Add public-facing Threat Modeling & Security website section
- Update benchmarks page to run 4 and add resource usage
- Run-4 analysis — post-fix matrix verified, resource usage, prod-limit guidance
- **⚠ BREAKING — a certificate-authenticated device now receives a machine
  token (`aud: axiam:m2m`), not a user token.** `POST /api/v1/auth/device`
  stamped `aud: axiam:user`, so any device that authenticated by mTLS passed
  **every** user-facing route guard. It now stamps `axiam:m2m`, matching the
  client-credentials grant: a service account is the same principal however it
  authenticated, and §4.3/`SEC-006` route narrowing finally applies to both.

  **What breaks.** A device token is no longer accepted on user-facing REST
  routes. It *is* accepted on the authorization-check endpoints — `POST
  /api/v1/authz/check` and `/api/v1/authz/check/batch` — which are the
  machine-facing surface and were widened in the same change so that no
  required device call started failing. Any other endpoint a fleet calls with a
  device token must be migrated deliberately; that access was implicit rather
  than designed.

  **Before upgrading**, check whether your devices call anything beyond the
  authz-check endpoints. SDK guards fronting a resource server that accepts
  device callers must be configured to expect `axiam:m2m` (`CONTRACT.md` §10.1
  rule 6, §12.1) — a guard set to `axiam:user` will now reject device tokens,
  which is the narrowing working as intended.

  gRPC is unchanged: its interceptor accepts both audiences on all services, so
  the m2m/user split is REST-only.

### Fixed

- Supply the mandatory auth pepper to release-mode stacks
- Propagate session-revocation failures; warn on mintable rate-limit key; verify remediation evidence
- Decouple gRPC admin ceiling from authz; bound infra family; tenant-filter member_of; reorder session-cache invalidation
- SDK bench correctness/telemetry + run-5 harness prep (I9-I19)
- Correct gRPC units, scope limits per method, revise internet defaults
- **The cache-invalidation publisher no longer serialises mutations behind a
  network round-trip (§15.3.4).** The channel-slot mutex was held across the
  broker confirm, so every access-narrowing mutation in the process queued on
  one lock while the heartbeat task contended for it — a throughput cliff under
  a slow broker, and a regression against the pre-§13.4 code, which shared the
  channel with no lock at all. The lock now covers only channel acquisition. The
  failure path clears the slot **only if it still holds the same channel**, so a
  concurrent reopen is not discarded.

- **`with_previous_pepper` now carries the weak-pepper warning (§15.3.7)** that
  `from_pepper` has always emitted. Lower impact — a previous key can only
  verify existing hashes, never produce one — but an operator rotating *away*
  from a weak pepper is precisely who should be told it was weak.

- **Cache-invalidation liveness heartbeats (§13.4 observation 1).** Decision-cache
  trust followed **consumer** liveness alone. A party with broker `configure`
  rights could `queue.unbind` a replica's queue from the fanout exchange and the
  replica would notice nothing: its consumer stays subscribed to a queue nothing
  routes to, so trust stays on and it keeps serving cached allows it will never
  be told to invalidate. The publisher sees nothing either — `mandatory` is off,
  so the broker acks an unroutable message. Invalidations were silently
  suppressed, bounded only by `decision_cache_ttl_secs`.

  Each replica now publishes a **self-addressed heartbeat** every
  `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS` (default `10`) and
  watches for its own to come back — a round trip that exercises the whole loop
  (publish → exchange → binding → queue → consumer), so an unbound queue breaks
  it immediately. After three consecutive missed intervals the cache is marked
  UNTRUSTED and the replica falls back to uncached evaluation.

  The watchdog can only **revoke** trust, never grant it: trust is still granted
  in exactly one place, by the consumer on a successful subscribe, so it can
  never resurrect trust on a replica whose consumer has died. Heartbeats never
  touch the cache and never enter the replay-nonce guard. Only applies when
  cross-replica broadcast is enabled. (Superseded below: heartbeats can no
  longer be disabled, and the interval is clamped to `1..=60`.)

- **Cached authorization decisions are now invalidated on user delete/update
  (§13.4 observation 9).** `users::update` and `users::delete` did not invalidate,
  so a deleted or deactivated user's cached `Allow` survived on every replica
  until the TTL expired. Nothing on the session-authenticated request path
  re-reads user status, so the cache was the only place the stale grant could be
  cleared. Both handlers now flush the affected subject.

- **Pepper rotation is no longer an unversioned hard break (§13.4 observation 3).**
  `AXIAM__AUTH__PEPPER` keys client-secret hashing, and the `v2.hs256$` tag
  versions the *algorithm*, not the *key* — so rotating the pepper invalidated
  **every** client secret at once, and every OAuth2 client and service account
  had to be re-issued in lockstep with the restart.

  Set the new `AXIAM__AUTH__PEPPER_PREVIOUS` to the outgoing value for the
  duration of a rotation: pre-rotation hashes still verify, and each secret is
  transparently rewritten under the new pepper the first time its owner
  authenticates, so the rotation drains itself with no downtime and no
  re-issuance. Nothing is ever *written* under the previous key. **See the
  rotation procedure in `docs/deployment/README.md` before rotating.**

  A stored key id was deliberately not used instead: it would hand anyone with a
  table dump an offline oracle for testing pepper guesses, which does not exist
  today. Both keys are tried unconditionally while a rotation is configured, so
  response time does not reveal which pepper era a row is in.

- **Service-account client secrets can now migrate hash schemes (§13.4
  observation 4).** `service_account` wrote the current scheme on create/rotate
  but had no `upgrade_client_secret_hash`, so an existing row never migrated no
  matter how often it authenticated — meaning the legacy v1 verifier arm could
  not be retired on the strength of "no v1 `oauth2_client` rows remain". The
  repository now exposes the same tenant-scoped compare-and-swap upgrade the
  OAuth2 client repository has, which also carries pepper-rotation rewrites.
  (Superseded above: the seam has no production caller because nothing verifies
  a service-account secret, so these rows migrate by **rotation**, not lazily.)

- **The cache-invalidation publisher recovers its channel (§13.4 observation 2).**
  It held one channel created at startup and never replaced, while the consumer
  side was fully supervised with backoff — so a single channel-level exception
  made every access-narrowing mutation return `503` for the rest of the process
  lifetime, clearing only on restart. The channel is now opened lazily and
  reopened after any failure.

- **Cross-replica authorization decision-cache invalidation over RabbitMQ (§4.2, threat-model `T-88`).**
  The decision cache invalidated **process-locally**: on a replica that did not
  handle the mutation, a revoked grant could stay `Allow` until its entry
  TTL-expired (default 5 s). That residual was documented and accepted; it is
  now closable. Setting `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`
  (on top of `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`) publishes every
  invalidation to the **fanout** exchange `axiam.authz.cache.invalidate`; each
  replica binds its own exclusive auto-delete queue
  `axiam.authz.cache.invalidate.<replica-uuid>` and applies what it receives,
  so a revocation reaches *all* replicas in broker-latency time. Fanout, not a
  work queue: a shared queue would deliver each invalidation to exactly one
  consumer and leave every other replica stale.

  **Default off, and inert when off.** With the switch unset, `invalidate_*` is
  local-only and infallible, no AMQP dependency is acquired by enabling the
  cache, and the previously documented TTL-bounded behaviour is unchanged.

  **Two deliberate behaviour changes when it is on**, both loud:
  - A mutation whose broadcast the broker does not confirm returns **503**
    (`"could not be broadcast to other replicas"`). The database write is
    durable but the fan-out did not happen, and reporting success would hand
    back the TTL window the operator enabled this to remove. These mutations are
    idempotent in the narrowing direction — retry is safe.
  - A replica whose invalidation consumer is not connected (startup, broker
    outage, partition) **stops serving from its cache** and evaluates every
    check against the database — correct, just slower — instead of serving
    allows it can no longer invalidate. Logged at ERROR
    (`AuthZ decision cache UNTRUSTED …`) and surfaced as `trusted` / `bypassed`
    on the periodic `AuthZ decision cache stats (D7)` line. Trust follows the
    consumer's connection liveness **only** — no inbound message can revoke it,
    so a captured broadcast cannot be used as a cache-disabling lever.

  Messages carry the existing §8 envelope (`CacheInvalidationMessage`):
  per-tenant HKDF-SHA256 subkey, `key_version >= 2` floor, per-message `nonce`,
  and an `issued_at` freshness window
  (`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS`, default 30 s, tighter
  than the 5-minute AMQP default because an invalidation is only useful for
  about as long as the cache TTL). Nonce dedup is **per replica, in memory** —
  never the shared durable nonce store, which on a fanout would let one replica
  win and make all the others reject the invalidation as a replay. The
  publisher's own echo is a no-op, and cannot loop: a received message only ever
  reaches `DecisionCache`, never the publishing path. Granularity is exactly the
  cache's existing `invalidate_subject` / `invalidate_tenant`; no finer key is
  invented.

  Requires `AXIAM__AMQP__SIGNING_KEY` (already mandatory) to be shared by every
  replica. Documented in `docs/deployment/README.md`, `docs/admin/README.md` and
  `docs/deployment/authz-read-path.md`.

- **Client secrets are now hashed with HMAC-SHA256 keyed by the server pepper (OBS-1).**
  OAuth2 client secrets and service-account secrets were stored as an unsalted,
  single-round SHA-256 digest — safe only while every secret is 32 CSPRNG bytes with
  no operator-supplied path, an assumption held by nothing stronger than a code
  comment. The digest is now keyed, so a database dump is not offline-attackable
  without the pepper, and the guarantee no longer depends on secret entropy.
  HMAC rather than a KDF is deliberate: the client-credentials grant stays
  MAC-bound, not KDF-bound, and does not regress (verification is now
  allocation-free, where it previously allocated a `String` per request).

  **Operator action required.** `AXIAM__AUTH__PEPPER` is now **mandatory** — a
  release build fails closed at startup if it is unset, the same posture as
  `AXIAM__AUTH__SIGNING_KEY`/`AXIAM__AMQP__SIGNING_KEY` (SECHRD-08 / D-05c).
  There is no unkeyed fallback: silently degrading when unconfigured is exactly
  what OBS-1 objected to. A debug build resolves a documented dev-only pepper
  with a warning. Do not change the pepper after deployment without re-issuing
  every client secret — v2 hashes are not portable across peppers.

  Existing hashes cannot be re-derived (only the digest was stored), so the
  scheme is versioned and migrates lazily. Stored hashes are now tagged
  `v2.hs256$<hex>`; an untagged 64-hex value is verified against the legacy
  scheme and, **on a successful verification only**, rewritten in the new scheme
  with a compare-and-swap so a concurrent secret rotation is never clobbered. A
  failed verification never rehashes and never writes. No schema change and no
  backfill: migration completes as each client next authenticates.

  `axiam_db::hash_client_secret` is removed; hashing is a method on
  `axiam_auth::client_secret::ClientSecretHasher`, so no call site can hash
  without a key. `OAuth2ClientRepository` gains `upgrade_client_secret_hash`
  (breaking for out-of-tree implementors).

- **Session-revocation failures are no longer silently swallowed (OBS-3).**
  `invalidate`, `invalidate_user_sessions` and `cleanup_expired` never checked
  the DELETE result, so a statement-level database error was discarded and the
  method returned `Ok(())` — logout, password-reset revocation and MFA reset
  reported success when the statement may have failed. All five session-deleting
  methods now propagate a `DbError`. Cache invalidation is deliberately ordered
  *above* the newly-fallible step in every path, so a failing DELETE cannot
  strand a positive cache entry.

- **Startup advisory when the rate-limit bucket key is attacker-mintable (§4.1).**
  Under `AXIAM__RATE_LIMIT__KEY=client_id` the whole bucket key is read from the
  unauthenticated form body before the credential check, so a caller rotating
  `client_id` values mints fresh buckets. The shipped default (`ip`) is silent;
  `client_id` now emits a `warn!` naming the caveat and pointing at the sizing
  guide, and `ip_client_id` a softer `info!` — its unforgeable IP half confines
  the collateral to the attacker's own source.
- **gRPC admin ceiling no longer derives from the read-sized authz ceiling
  (SEC-079).** See the entry below for the units correction that made this
  necessary.

### Security

- **A client-existence oracle survived on the `authorization_code` grant
  (SEC-086, second pass).** The first pass unified every token-endpoint
  `error_description` behind one constant, but only two of the three grants
  ordered their checks safely. On `authorization_code` the client lookup ran
  *before* the secret-presence check and the grant-type check ran *before*
  secret verification, so an unauthenticated caller could still separate "no
  such client" from "client exists" — with no secret at all, and again with any
  dummy secret. Both checks now follow verification, matching
  `client_credentials` and `refresh_token`. `unauthorized_client` is now
  reachable only by a caller who has already proven possession of the secret.

- **The failed-client-auth audit row could be written into any tenant
  (SEC-087).** `/oauth2/token` is unauthenticated and takes `tenant_id` from a
  query parameter, so the audit row added in the previous change let an
  anonymous caller append rows to an arbitrary — or nonexistent — tenant's
  append-only log. The tenant is now resolved before the write; the
  caller-supplied `client_id` is truncated; and the recorded IP is the
  transport peer address, with the forgeable `X-Forwarded-For` value kept in
  metadata under a name marking it untrusted.

- **Neither half of the decision-cache staleness bound is operator-removable any
  more (§15.2).** Two gaps compounded: `decision_cache_ttl_secs` was an
  unbounded `u64` (unlike `cleanup_interval_secs`, clamped since T-04-35), and
  the cross-replica heartbeat that shortens the undelivered-invalidation window
  could be switched off with `..._HEARTBEAT_SECS=0` and only a warning. An
  operator could therefore set a multi-hour stale-allow window *and* disable the
  mechanism that detects a replica whose queue has been unbound.

  The TTL is now clamped to 300 s — in the accessor `build_decision_cache`
  calls, not in `main.rs`, so every construction path is covered. Heartbeats
  cannot be disabled while broadcast is on; out-of-range intervals clamp to
  `1..=60`. The `0` escape hatch was introduced in this same unreleased change,
  so removing it breaks nothing.

- **A replayed heartbeat can no longer satisfy the liveness watchdog (§15.2).**
  Heartbeats bypass the replay `NonceGuard` deliberately — they arrive on a
  fixed interval from every replica and would evict real invalidation nonces
  from its bounded capacity. That left a narrow path: a party with broker rights
  who captured one signed heartbeat could replay it inside the freshness window
  to keep a replica's watchdog satisfied while its queue was unbound, which is
  the exact adversary the heartbeat exists to detect. Acceptance is now bound to
  nonces the replica itself published and has not yet seen back.

## [1.0.0-alpha23] - 2026-08-02

### Added

- Rust benchmark improved release build optimizations
- Present the client certificate in the PHP SDK bench
- Wire TLS into the C# SDK bench (CA + client certificate)
- Present the client certificate in the TypeScript SDK bench
- Wire TLS into the Kotlin SDK bench (CA + client certificate)
- Present the client certificate in the Java SDK bench
- Present the client certificate in the Python SDK bench
- Present the client certificate in the Rust SDK bench
- Present the client certificate in the Go SDK bench

### Changed

- All eleven SDK benches now pass the client-cert gate
- Complete the STRIDE threat model in Threat Dragon format

### Fixed

- Make the p2-tls13 and p3-mtls SDK matrices pass
- Make the p3-mtls path actually reachable end to end

## [1.0.0-alpha22] - 2026-07-31

### Added

- Add a dry-run mode to rehearse the matrix in minutes
- Raised RAM resources in benchmarks to improve Keycloak performance (Axiam and Zitadel performs well even with 1024m)
- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- gRPC rate limits are now scoped **per method family** instead of server-wide (I2). One
  bucket each for authz-check (`axiam.v1.AuthorizationService`), identity-read
  (`axiam.v1.UserInfoService`, `axiam.v1.TokenService`) and admin
  (`axiam.v1.UserService`), with gRPC reflection and health explicitly never limited and
  an unrecognized path failing safe into the strictest bucket. Two new knobs,
  `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` (default 5x the authz ceiling = 500/s) and
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (default a flat 10/s — see the posture note under
  *Security* below); leaving `GRPC_IDENTITY_PER_SEC` unset derives it from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, so a posture preset still moves that pair with one
  variable. Previously a `GetUserInfo` read — measured at 12 665/s — was throttled
  by the *authz* ceiling, because a single server-wide bucket made an authorization sizing
  decision into a userinfo sizing decision
- Startup advisory for mis-sized machine limits: when the shipped `internet` defaults are
  what a process is actually enforcing (no posture preset, no machine limit pinned by
  hand) and the sustained 429 ratio on the machine endpoints exceeds ~50% over a 5-minute
  interval, the server logs "your limits are throttling what looks like legitimate machine
  traffic; see rate-limit-sizing". Built on the write-behind rate-limit counter's existing
  flusher pass — no new background task, no new timer, and human endpoints are excluded
  from the ratio by construction (a 429 storm on `/auth/login` is a credential-stuffing
  signal, not a sizing signal)
- Benchmark dry-run mode (`just bench-dry-run`, `just dry=1 bench-run`) — rehearses the
  whole target × profile matrix over the same bring-up/seed/run/tear-down path in minutes,
  grading each cell on the k6 client contract (connect, request, expected response) instead
  of on performance, so a break surfaces before an hours-long matrix commits to it
- Optional **session-validation cache** (I6), `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`
  (default `0` = off). Every authenticated REST request re-reads the `session` row behind
  the access token's `jti` to enforce D-15 revocation; that read is not covered by the
  authorization decision cache, which is why turning the decision cache on lifted gRPC
  authorization checks 13.1x but REST checks only 5% in benchmark run 4 — the gRPC
  interceptor has no equivalent read. The cache stores **positive answers only**, carries
  each session's own `expires_at` (so expiry is never extended), and is invalidated by every
  session-deleting method on the repository, so on a single replica a logout still takes
  effect immediately. Multi-replica deployments inherit the same bounded-staleness caveat as
  the decision cache and should leave it off or match its TTL
- `AXIAM__SERVER__TCP_NODELAY` (default `true`, I5) — actix-web leaves `TCP_NODELAY` unset
  unless asked, so the REST listener ran with Nagle's algorithm enabled while the gRPC
  listener (tonic, which defaults it on) did not. Set `false` to restore the previous
  behaviour for A/B measurement
- Per-stage timing instrumentation on the OAuth2 client-credentials path (I5) —
  `client_lookup_us`, `secret_verify_us`, `tenant_lookup_us`, `token_mint_us`,
  `handler_total_us` on the `oauth2.client_credentials` span, plus `exchange_us`,
  `serialize_us` and `response_body_bytes` from the token endpoint, re-emitted as DEBUG
  events on `target: "axiam::perf"`. Measurement is unconditional (five `Instant::now()`
  reads, well under 0.1% of the handler) and only reporting is gated by the tracing level
- `crates/axiam-db/tests/authz_query_plan_test.rs` — `EXPLAIN`-based query-plan pins for
  the authorization hot path, so a rewrite that reintroduces a table scan fails in CI rather
  than in production. Includes witness tests proving the removed forms really did scan
- [`docs/deployment/authz-read-path.md`](docs/deployment/authz-read-path.md) — what one
  authorization check costs against SurrealDB, which cache removes which round-trip, and a
  design note on read-replica topology for authorization reads (analysis only; not
  implemented)

### Changed

- Revised the shipped `internet` machine-endpoint rate-limit defaults (I3), sized from the
  run-4 measured capacity of each endpoint: `TOKEN_PER_MIN` 20 → **120**,
  `INTROSPECT_PER_MIN` 10 → **600**, `AUTHZ_CHECK_PER_MIN` 300 → **1800**,
  `REVOKE_PER_MIN` 10 → **60**. The old numbers sat four to five orders of magnitude below
  the machine's ceiling (token 20/min against ~163 000/min of capacity) and broke the first
  healthy integration behind a NAT without protecting anything the new ones fail to
  protect; every revised value still stays 25–2 700x below measured capacity. **Human
  endpoints (login, register, password-reset, MFA) are unchanged** — they are sized against
  credential guessing, never against capacity. The `gateway`/`mesh` presets are unchanged.
  If you pinned any of these with an env var, nothing changes for you: explicit env still
  beats both the preset and the shipped default

### Fixed

- Hold a live pool reference in repositories, not a boot-time clone
- Two **full table scans on the authorization hot path** (I7). Every uncached authorization
  check — REST, gRPC and AMQP alike — walked the whole `grants` table (every role-to-permission
  grant of every tenant) and the whole `has_role` table (every role assignment of every user
  of every tenant), because both predicates were written in forms the SurrealDB planner
  cannot serve from an index: `WHERE meta::id(in) IN $role_ids` wraps the indexed field in a
  function call, and `WHERE in IN (SELECT VALUE out FROM member_of WHERE ...)` leaves a
  correlated sub-select on the right-hand side. `EXPLAIN` reported
  `TableScan { pre_decode_filter: "no (unsupported predicate)" }` for both. They now compare
  against bound record ids and a pre-resolved `LET` binding respectively and plan as
  `IndexScan` over the existing `idx_grants_unique` / `idx_has_role_unique` composite indexes
  — no schema change, identical rows returned. The cost was invisible on a small seed and
  grew with total database size, which is consistent with SurrealDB showing up as the
  product's throughput ceiling in benchmark run 4
- gRPC rate limits were enforced at **1/60th of the configured rate** (I1). The gRPC
  ceiling is per second, but the cross-replica shared pre-check runs the same fixed
  60-second window as the REST limiter and was handed the per-second number verbatim; since
  the stricter of the two cooperating layers wins, `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100`
  admitted ~100 requests per *minute*. The per-second → per-window conversion now happens
  once, at the layer boundary, with a saturating multiply, and the production constructor
  takes per-second ceilings so a caller cannot get the units wrong again. Found by benchmark
  run 4's production-posture pass. **Read the gRPC admin-ceiling entry under *Security*
  below before upgrading** — correcting these units raised every gRPC ceiling 60x, which is
  a posture change and not only a units fix
- Stale DB handles after a reconnect: every repository was built at boot from a one-time
  `pool.handle_for_repo()` **clone** of the pooled SurrealDB connection, so when the pool's
  reconnect loop evicted a poisoned connection (observed ~7 minutes into a sustained load
  run) every repository stayed pinned to the dead one and returned 401 permanently until
  the process restarted — while `/ready`, which probes through the pool slot, still
  reported healthy. Repositories now hold a live `DbHandle` over the pool slot and resolve
  the current connection per query, so a swap is picked up on the very next query. The REST
  `AppState.db` (bootstrap handler, tenant seeder) and the gRPC layer's handle held the same
  boot-time clone and were fixed the same way
- `meta.json` could be written as invalid JSON when a host fact spanned two lines — a
  `docker version` against an unreachable daemon prints an empty line and *then* fails, so
  the `|| echo unknown` fallback produced a literal newline mid-string and took `report.py`
  down with an "Invalid control character" for the whole run

### Security

- **gRPC admin/credential-check ceiling is now an absolute 10/s (600/min per IP), not the
  authz ceiling (SEC-079). This is a posture change — read it even if you skipped the
  units fix above.** Correcting the gRPC rate-limit units (I1, under *Fixed*) changed what
  every gRPC ceiling actually enforces from `N` per **minute** to `N` per **second**. The
  units bug had been accidentally supplying 60x more protection than the configuration
  said, so an operator who reads only "corrected gRPC units" will not realise their
  deployed gRPC ceiling rose 60x on upgrade. That matters most on
  `axiam.v1.UserService/ValidateCredentials`, which performs a real Argon2id password
  verification (~19 MiB of memory arena each): its per-IP ceiling would have gone from
  ~100/min to ~6 000/min — a 60x increase in online password-guessing throughput and in the
  Argon2id CPU a caller can conscript. The admin family therefore no longer derives from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` at all; it takes a CPU-appropriate absolute default of
  10/s, unchanged by `AXIAM__RATE_LIMIT__PROFILE`, so raising the authz ceiling for
  service-mesh capacity can no longer widen credential guessing as a side effect. The
  family holds only `GetUser` and `ValidateCredentials`; the high-volume identity read is
  `GetUserInfo` on `UserInfoService`, which is in the identity-read family and unaffected.
  **Action:** if a provisioning or admin workload legitimately exceeds 600 `UserService`
  calls per minute from one source IP, pin `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` — explicit
  configuration still wins over both the default and any posture preset. Per-account
  lockout, the shared failure metering and the process-wide crypto semaphore are unchanged
- gRPC reflection and health are no longer an **unlimited pass-through**. The family is
  selected by prefix-matching the client-supplied gRPC `:path` (`/grpc.reflection.`,
  `/grpc.health.`) and used to bypass both limiter layers entirely. Neither service is
  registered today — requests terminate `Unimplemented`, so the practical effect was
  unmetered HTTP/2 stream churn rather than database work — but registering a health
  service would have made it a genuinely unmetered endpoint. It now has its own bucket at a
  fixed 100/s per IP: orders of magnitude above any real probe cadence, so a liveness probe
  still answers during an incident when every other family is saturated, while the surface
  stops being unbounded
- Group-membership traversal on the authorization read path now carries a read-time tenant
  predicate. `get_user_role_assignments` resolved `member_of` edges with no
  `out.tenant_id` filter; this was not exploitable — group membership is validated against
  the tenant at write time and the outer `has_role` predicate still confined the resulting
  role — but it left group-inherited roles as the one authorization edge with no read-time
  tenant check, so a migration or bulk import writing `member_of` directly would have
  bypassed it. The predicate is served by the existing `idx_member_of_unique` index; the
  query-plan pins confirm the plan is still an `IndexScan`
- Session-cache invalidation now runs immediately after the `DELETE` commits, before the
  deleted rows are deserialized, in `consume` and `invalidate_user_sessions_except`. The
  `DELETE` has already succeeded at the database once the await returns, so a deserialize
  failure of the returned BEFORE image used to return early and leave a **positive**
  session-validation cache entry live for up to the TTL — a deleted session that kept
  validating. Only reachable with the opt-in
  `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` enabled
- **Session revocation no longer reports success when the `DELETE` failed (OBS-3).**
  `SessionRepository::invalidate`, `invalidate_user_sessions` and `cleanup_expired` awaited
  their `DELETE` and returned `Ok(())` without ever calling `.check()` or `.take()`, so a
  statement-level SurrealDB failure was discarded — logout, password-reset session
  revocation and MFA reset all told the caller sessions were revoked when the statement may
  never have run. All five session-deleting methods now `.check()` the response and
  propagate a `DbError`, which surfaces as `500` at `POST /api/v1/auth/logout` and the GDPR
  disable path rather than as a silent `204`. Cache invalidation deliberately still runs
  **before** the new fallible step, so the ordering fix above cannot be reintroduced: an
  erroring `DELETE` drops the cache entry (costing at most one avoidable re-read) instead of
  stranding a positive "still valid" entry
- Startup **warning** when `AXIAM__RATE_LIMIT__KEY=client_id` is active. In that mode the
  rate-limit bucket key for `/oauth2/{token,introspect,revoke}` is the `client_id` read from
  the unauthenticated form body (RFC 6749 §2.3.1) **before** any credential check, so a
  caller rotating `client_id` values mints a fresh bucket per value; under this mode those
  limits are a fairness control between cooperating clients, not an anti-abuse control, and
  the mode assumes an edge (mTLS / API gateway / WAF) that already authenticates callers.
  The warning names that and points at `docs/deployment/rate-limit-sizing.md` §5. The
  shipped default (`ip`) is not attacker-mintable and stays **silent**; the partially
  mintable `ip_client_id` gets a softer `info!` note, because its source-IP half still
  prevents a third party from exhausting a known `client_id`'s bucket from elsewhere. No
  behaviour or limit changes — advisory only, matching the I3 machine-traffic advisory and
  the session-validation cache's startup `warn!`
- CI now verifies that **remediation evidence actually shipped**
  (`scripts/check-remediation-evidence.py`, wired into `docs-ci.yml`). A remediation record
  citing a commit hash is not evidence a fix merged — a hash exists the moment a commit is
  authored, on any branch, and the 2026-08-03 review pass caught a real instance (a Swift
  fix recorded as remediated while still unmerged). Every `(finding id, repo, commit)`
  triple in a remediation table of `claude_dev/security-analysis-*.md` must now resolve to a
  commit reachable from the default branch of the repo it claims: locally via
  `git merge-base --is-ancestor`, and for the out-of-tree SDK repos via the GitHub API when
  the token can read them. Rows that cannot be verified are printed as **SKIPPED by name**
  rather than passing silently, and a row that cannot be parsed into a triple **fails** the
  check naming the row

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha20.

## [1.0.0-alpha20] - 2026-07-30

### Added

- Opt-in rate-limit posture presets + TLS/h2 tuning surface (G7, G8 in progress)
- G9 — throttle-aware metrics and the gRPC/REST authz analysis
- G2 harness countermeasures, G4 refresh fix, G5 cache-sweep scenario
- Per-task data-collection script for the pre-MVP plan
- Run-3 benchmark page refresh + benchmark-derived sizing docs

### Changed

- Add the run-4 execution runbook
- Bump the version marker to 1.6 and record the follow-up audit findings
- Add §9 rule 6 — single-flight guard implementation invariants (contract 1.6)
- Bump frontend/coverage/website-publish Node from 20 to 22
- Bump jsonwebtoken from 10.4.0 to 11.0.0
- Bump jsdom from 29.1.1 to 30.0.1 in /frontend
- Use the obviously-fake password fixture convention in the users split test
- Verify the write-behind clamp fix on a local rl-fix-local build
- Document the write-behind shared counter and its security bound
- Note why REST and gRPC each hold their own shared counter
- Adapt the shared-store middleware suite to write-behind counting
- Serve shared rate-limit decisions from the write-behind counter
- Add write-behind SharedRateLimitCounter + increment_by
- Mark the bench admin default in h5-revocation-check.sh as a throwaway fixture
- H10(5): finalize §6 execution record with the validated H10 outcome
- H10(4): report.py — settle_timeout refusal is now scenario-aware, not session-wide
- H10(3): consistency pass — methodology.md §12 + append §6 execution record
- H10(2): E4 — fourth public benchmark draft
- H10(1): consistency pass — reconcile PRIVATE_BENCH_ANALYSIS.md with H2/H3/H4/H5/H9 verdicts
- H8(5): profile-scope SDK result storage, README truthful status table, per-language TODO notes
- H8(4): wire BENCH_CA_CERT into 5 SDK benches for p2, integrate E1.3 overhead table into report.py
- H8(3): fix refresh-op concurrency in python/typescript benches (HARNESS-SPEC required conc=1, neither implemented it)
- H8(2): fix server CSRF header-echo + go bench org_slug — both blocked every SDK bench end-to-end
- H8(1): per-language SDK bench fixes — rust seed env, python venv, ts npm link, go.sum, java compile, csharp preflight, php minimum-stability
- H7(1): confirm the REST/gRPC classifier wiring live; correct the stale G9 note
- H7(3b,4): measure the gateway rate-limit preset live; close the Keycloak p0-vs-p2 login asymmetry
- H7(1,3a,5): protocol-variant label, maintainer sign-off block, H4 control-build fix
- H6(7): measure the CC clamp control instead of asserting it, and price the noise
- H6(6): publish the B2 position — TLS priced, HTTP/2 acquitted, CC still open
- H6(5): close B2 in the private analysis
- H6(4): document bench_http_proto in the methodology metric list
- H6(3): the h2 hypothesis is refuted by counting connections
- H6(2): h6-tls-proto task + a connection/worker-affinity probe
- H6(1): capture the negotiated HTTP protocol, and make the h1 control honest
- H5(4,5): decision-cache verdict — default STAYS opt-in, flip blocked on C1/C2/C4
- H5(3): automate the live-stack revocation check; run the K-sweep under TLS
- H5(1): fix the three decision-cache defects surfaced by the G5 review
- H9: DB-pool default decision — keep pool_size=1, close negative
- H2: G1 endgame — the "post-seed transient" is the shared rate-limit write
- H1: drain pause after settle gate to prevent straggler-traffic contamination
- H4: jemalloc as the release-container default allocator (executes G6 PASS)
- H1.5: report.py refuses cells whose meta records settle_timeout:true
- H1.2: fix bench-matrix results-dir clobber + fail-fast task-script guard
- H1.1: settle gate v2 — concurrent burst probe replaces serial canary
- H3: flip authz batch strategy default to coalesced (G3 decision)
- Phase H plan from the verified 2026-07-28 G-task results
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Correct the published client_id rate-limit guidance with its security caveat
- G7 rate-limit posture decision record
- G8 security-profiles update + implementation status for the pre-MVP plan
- G8 — B2 HTTP/2 investigation and the ALPN knob fix
- Bump base64 from 0.22.1 to 0.23.0
- Bump the minor-patch group in /frontend with 12 updates
- Bump actions/download-artifact from 4.3.0 to 8.0.1
- Bump taiki-e/install-action from 2.83.2 to 2.85.2
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump docker/login-action from 3.4.0 to 4.5.1
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Run-3 analysis, D9 experiment script, pre-MVP improvement plan

### Fixed

- Select jsonwebtoken 11's rust_crypto backend explicitly
- Stop charging GET /api/v1/users to the users_create limiter
- Make g1-dbdirect's direct SurrealDB probe actually run
- Resolve g1-dbdirect's DB credentials from the running stack
- Interrupt-safe teardown for every task that holds a stack
- Unwedge the G1 tasks' telemetry sampler
- Dial gRPC over TLS in p3-mtls; record real gRPC status
- Resolve p3-mtls client cert path from any CWD

## [1.0.0-alpha19] - 2026-07-25

### Fixed

- Migrate react-router-dom v7 -> react-router v8 (GHSA-qwww-vcr4-c8h2)

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Workspace coverage improvements toward >=90% (T2-T6), scanner-clean
- Plan to push Coveralls badge over 90% with per-task model picks
- Ratchet line-coverage floor 77 -> 80 and surface achieved total
- Runtime-generate the new-password arg in confirm_reset test
- Close residual gaps in password_reset and pgp
- Satisfy rustfmt, clippy, and CodeQL on the new coverage tests
- Exclude axiam-server binary composition root from coverage
- Cover SAML/OIDC non-xmlsec logic and negative paths
- Broker-free seams for authz/audit consumers + fix auth rand_core
- Cover residual repository CRUD/error paths + seeder + nonce-replay
- Cover cleanup.rs expiry sweeps and erasure pipeline branches
- Cover federation/auth/webhook/password-reset/rbac error paths
- Round-2 test-coverage plan for server + C SDK with per-task model picks
- Bump docker/build-push-action from 6.15.0 to 7.3.0 (#213)
- Bump @testing-library/jest-dom in /frontend (#216)
- Bump actions/setup-node from 6.4.0 to 7.0.0 (#214)
- Bump dtolnay/rust-toolchain (#212)
- Test-coverage improvement plan for server + 11 SDKs (2026-07-23 baseline) (#227)
- Bump the minor-patch group in /frontend with 8 updates (#215)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#211)
- Bump actions/attest-build-provenance from 2.4.0 to 4.1.1 (#210)
- Correct model attribution and add phase dates to roadmap (#226)
- Rewrite laptop runbook for run 3 against released 1.0.0-alpha17

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies for security fixes

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add AXIAM gRPC userinfo scenario + protocol-efficiency pairing
- Implement UserInfoService and integration tests
- Add gRPC UserInfoService/GetUserInfo (contract 1.3)
- Add missing SDKs, gRPC + config docs, real benchmark data
- Implement run-2 follow-up tasks (A8, A9, D10, D11, report polish)

### Changed

- Use a random seeded-user password in userinfo tests
- Add gRPC userinfo implementation plan
- Run-2 analysis (1.0.0-alpha15) — update public/private bench docs + plan

### Fixed

- Make concurrent batch future boxable behind AuthzChecker trait

## [1.0.0-alpha15] - 2026-07-21

### Added

- F2 — DbPool of N independent handles, wire repositories, close CQ-B48
- F1 — connection-pool design doc + boundary instrumentation
- D7 — decision caching behind a flag (default off) with revocation invalidation
- D8 — configurable rate-limiter key (ip|client_id|ip_client_id)
- D3 — native mTLS (client-certificate) auth
- B1 — bound concurrent Argon2id hashing (perf + memory-DoS fix)
- AXIAM native (in-process) TLS for the p2-tls13 profile
- TLS profiles for keycloak + zitadel; RSA certs; port pre-flight
- Auto-provision Zitadel client via management API

### Changed

- Regression test for gRPC-over-TLS crypto provider
- Fix stale F1/F2 status rows (still showed "planned" post-merge)
- Mark E1.2 done (four stub SDK benches wired)
- Wire the four stub SDK benches (c, cpp, kotlin, swift)
- Cargo fmt F2 (DbPool)
- Cargo fmt F1 instrumentation wiring
- Laptop re-run runbook + Phase F (DB connection pooling)
- Cargo fmt (rustfmt CI fix)
- Per-task implementation status table
- D9 — optional jemalloc allocator for RSS-retention experiment
- Drive gRPC over TLS at p2 (native gRPC TLS wiring)
- B3 — JWKS in-process cache + HTTP caching headers (ETag/304)
- D1 — coalesce same-subject authz batches + tracing
- B2 — TLS 1.3 throughput diagnosis + fixes on token endpoints
- Zitadel gRPC benchmark coverage
- AMQP async-authz load harness design
- Real Zitadel login via session API v2 (password verification)
- SurrealDB tuning investigation — preliminary static analysis
- Re-run protocol — median-of-N, DB tuning, laptop runbook, prod posture
- Harness correctness & honesty (A1–A7)
- Expand plan E1 — implement & validate the SDK client benches
- Benchmark improvement implementation plan; refine throttling assessment
- Add public + private analysis of the first full benchmark run
- Re-enabled pepper and moved compose to latest AXIAM image version

### Fixed

- Make Keycloak and Zitadel seed users loginable
- Install ring rustls CryptoProvider so gRPC-over-TLS works
- Serialize F1 gauge tests against shared-static race (flaky CI)
- Give the E2E backend-startup step real timeout margin
- Correct actix test app-factory return type (D8 integration test)
- Fill new config fields in remaining test literals
- Clippy collapsible-if, grpc test field, OpenAPI drift
- Gate bench-up on target HTTP readiness

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Require organization context for login/refresh (#204)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Added

- Add --changelog to summarize commits into CHANGELOG.md

### Changed

- Wire org context into the TypeScript bench; list all 11 SDKs in README (#199)

### Fixed

- Wire Keycloak TLS via entrypoint; stop passing empty KC_HTTPS_*
- Correct image labeling metadata for GHCR
- Drop --optimized from Keycloak first start
- Dial gRPC plaintext regardless of HTTP TLS profile
- Merge tlsOptions() into gRPC scenarios so cert-skip applies
- Skip k6 server-cert verify for private-CA TLS profiles
- Neutralize rate limits so p0 measures endpoint capacity
- Apply the configured password pepper when hashing the admin (#200)
- Don't set AXIAM__AUTH__PEPPER (breaks bootstrap-admin login)
- Write resource CSV rows; configure OAuth2/optional secrets; skip OAuth2 when unset
- Supply org context on login; make bench-down work without secrets
- Provide mandatory AMQP signing key for the AXIAM target
- Bootstrap AXIAM secrets in bench-up; auto-track image tag
- Correct just variable-override ordering so bench-matrix works

## [1.0.0-alpha3] - 2026-07-16

Third alpha. Build/release tuning and project-infrastructure changes only. No
server runtime or API behavior changes — the OpenAPI specification is
byte-for-byte identical apart from its `info.version` string.

### Added

- **Public marketing & documentation website**, deployed to GitHub Pages.

### Changed

- **Release build profile** — added `[profile.release]` to the workspace-root
  `Cargo.toml`, tuned for execution speed first and footprint second:
  `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.
  Cargo only honors profiles at the workspace root, so this single section
  covers `axiam-server` and every crate it links. `panic = "abort"` is
  intentionally omitted to preserve per-request panic isolation on the
  long-running REST/gRPC/AMQP server. Release builds are slower in exchange for
  faster runtime.

## [1.0.0-alpha2] - 2026-07-16

Second alpha. Adds the SDK declarative-authorization contract and release-prep
polish; no server runtime/API behavior changes.

### Added

- **CONTRACT.md §11 — Declarative Authorization Helpers**: the canonical
  `require_auth` / `require_access(action, resource[, scope])` / `require_role`
  vocabulary layered on the §10 guard, with the per-language naming map and
  normative semantics (subject propagation, 401/403/400/503 error mapping,
  fail-closed on transport error, no decision caching). Marked SHOULD-level and
  recorded as non-breaking/additive; contract version bumped to 1.1.
- README build/coverage/license badges.

### Changed

- Roadmap "Development Progress": Phase 17 (SDKs) and Phase 18 (security audit)
  marked Done.

### Fixed / CI

- Added a free-disk-space step to the heavy Rust `test` and `cargo-llvm-cov`
  jobs to prevent the RabbitMQ disk-space alarm that intermittently failed CI.

## [1.0.0-alpha1] - 2026-07-16

Patch release over `1.0.0-alpha` that fixes the release pipeline so the
aarch64 server binary and the OpenAPI drift gate build cleanly. There are no
functional or API changes — the OpenAPI specification is byte-for-byte
identical apart from its `info.version` string.

### Fixed

- **aarch64 release build** — the *Build Release Binary (aarch64)* job failed
  at "Install build dependencies" because the native `ubuntu-24.04-arm` runner
  intermittently could not reach `ports.ubuntu.com` (IPv6 unreachable, IPv4
  timeouts). The apt step now forces IPv4, prefers Azure's in-network ports
  mirror, and retries with backoff, without changing the installed package set.
- **OpenAPI version drift** — the REST spec's `info.version` was a hardcoded
  literal that fell out of sync with the crate version and failed the OpenAPI
  drift gate. It is now bound to `CARGO_PKG_VERSION`, so it always tracks the
  workspace version and cannot drift on a future version bump.

[1.0.0-alpha1]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha1

## [1.0.0-alpha] - 2026-07-15

First alpha release of AXIAM (Access eXtended Identity and Authorization
Management). This is an early, pre-production preview intended for evaluation
and feedback — APIs and data models may still change before the beta and
stable releases.

### Added

- **Multi-tenancy** — organizations as top-level entities containing fully
  data-isolated tenants; all domain entities (users, groups, roles,
  permissions, resources, certificates) are tenant-scoped.
- **Authentication** — username/password (Argon2id), MFA (TOTP), social login
  and certificate-based (mTLS) authentication; EdDSA (Ed25519) JWT access
  tokens with opaque, single-use, rotating refresh tokens.
- **Authorization** — additive, default-deny RBAC engine with role
  inheritance through hierarchical resources, scopes for sub-resource
  granularity, and group-inherited role assignments.
- **OAuth2 / OpenID Connect** — authorization server and OIDC provider
  (Authorization Code + PKCE, Client Credentials, Refresh Token).
- **Federation** — SAML SP and OpenID Connect federation for cross-domain SSO.
- **APIs** — REST (Actix-Web, OpenAPI-documented), gRPC (Tonic) for
  low-latency authz checks, and AMQP (Lapin) for async/deferred authz, audit
  ingestion and event notifications.
- **PKI** — per-tenant X.509 certificate management signed by an organization
  CA, with CA private keys encrypted at rest (AES-256-GCM); GnuPG/OpenPGP
  integration for audit signing and encrypted data exports.
- **Auditing** — append-only audit logging.
- **Webhooks** — real-time event notifications to external systems, signed
  with HMAC-SHA256.
- **Admin frontend** — React + TypeScript administration UI.
- **Packaging & deployment** — multi-arch (amd64/arm64) container images and
  standalone server binaries, Docker Compose and Kubernetes manifests.
- **Client SDKs** — Rust, TypeScript, Python, Java, C#, PHP and Go SDKs, each
  released in its own repository against the shared API contract.

[1.0.0-alpha]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha
