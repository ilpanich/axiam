# Competitor gap remediation plan — 2026-10-02

> **Status: ACCEPTED — in execution as Phase 23.** W1 (G-1 X7.1–X7.3, G-4,
> G-9, G-12, G-15) executed 2026-10-02/03 on `claude/phase23-w1` and merged
> (PR #521); D-9 and D-10 taken during it. W2 (G-1 X7.4–X7.9 and the
> submission package, T23.1.8, G-3's crate and bind path) runs on
> `claude/phase23-w2`: D-11 taken by the maintainer on 2026-10-03 (option 1,
> issue #516), D-12 and D-13 accepted as recommended. Written against AXIAM `1.0.0-beta17` from the three
> comparisons in this directory:
> [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md)
> (Keycloak 26.8.0),
> [`competitor-comparison-zitadel.md`](competitor-comparison-zitadel.md)
> (Zitadel v4.19.4) and
> [`competitor-comparison-authentik.md`](competitor-comparison-authentik.md)
> (authentik 2026.8.3). Each item below is grounded in the current tree; where a
> comparison's claim about AXIAM was checked against the code, the finding is
> recorded under *Today*. As items land, each section gets an `EXECUTED` block
> at its head, in the form [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md)
> uses.

The three comparisons agree on one thesis: AXIAM wins on **authorization depth,
high-assurance OAuth, PKI, efficiency and safe defaults**, and loses on
**enterprise integration** (SAML issuance, directories), **certification** and
a handful of newer protocol surfaces. This plan turns the three gap lists into
one ranked list, drops what the comparisons themselves say not to chase, and
proposes a phase of work with dependencies, acceptance criteria and the
bookkeeping each item owes (contract, threat model, website, SDKs).

---

## 1. Method

Each gap named by at least one comparison was scored on three questions:

1. **Breadth.** How many of the three competitors have it, and at what
   maturity (GA, preview, experimental, enterprise-only)?
2. **Positioning.** Does the gap block AXIAM's own niche (machine and IoT
   first, strict multi-tenancy, enterprise-grade), or would closing it turn
   AXIAM into a product it does not want to be (an application portal)?
3. **Leverage.** How much of the work is already in the tree, and does the
   gap sit on top of something AXIAM is uniquely good at (the integrated CA,
   the revocation feed, the AMQP event spine)?

Consolidated priority follows the comparisons' own three tiers. Where the
three documents disagree, the stricter reading was kept and the reason is
noted. The comparisons' *P3 — watch, do not chase* items are kept as explicit
decisions rather than dropped silently: a gap nobody wrote down is a gap the
next reviewer rediscovers.

---

## 2. Consolidated gap matrix

Legend for the competitor columns: **GA** generally available, **Pv** preview,
**Ex** experimental, **Ent** enterprise licence only, **—** absent, **?**
not documented.

| # | Gap | Keycloak | Zitadel | authentik | Priority in comparisons | **Consolidated** | Today in AXIAM |
|---|---|---|---|---|---|---|---|
| G-1 | OpenID / FAPI 2.0 certification | GA (FAPI 2.0 passed) | not reachable (no PAR/DPoP/mTLS) | GA (OP + logout, 2026.8) | K P1, A P1 | **P1** | Suites run on demand (`fapi-conformance.yml` is `workflow_dispatch` only); 2026-09-25: Basic OP 30/35 (4 `REVIEW`), FAPI 2.0 34/37 and 52/56 (2 `REVIEW`, 1 `WARNING`). X7 is planned with no code yet; X5 submission not sent |
| G-2 | SAML 2.0 identity provider | GA | GA | GA (+ WS-Fed Ent) | K P1, Z P1, A P1 | **P1** | SP only (`crates/axiam-federation/src/saml.rs`, 3 527 lines, behind the `saml` feature) |
| G-3 | LDAP / Active Directory as a user source | GA (+ Kerberos) | GA (external IdP) | GA (+ Kerberos, nested groups) | K P1, Z P1, A P1 | **P1** | Nothing: no crate, no model, no mention in the design document |
| G-4 | RFC 7592 client configuration endpoint | GA | GA (v4.17) | — | Z P2 | **P2** | RFC 7591 only; `dcr.rs` returns no `registration_access_token` and records 7592 as deferred |
| G-5 | Shared Signals Framework transmitter (CAEP / RISC) | Ex | — | Ent | K P2, A P2 | **P2** | Revocation feed `GET /oauth2/revocations` (R-6), webhooks, Reactors — the ingredients, not the protocol |
| G-6 | Outbound SCIM provisioning | — | — | GA | A P2 | **P2** | Inbound SCIM server only (`crates/axiam-scim`) |
| G-7 | CIBA (OpenID client-initiated backchannel authentication) | GA | — | — | K P2 | **P2** | Nothing |
| G-8 | Whole-stack resting footprint; AMQP mandatory | n/a | wins this cell | not measured | Z P2 | **P2** | Broker is a hard dependency: the server refuses to boot without an AMQP signing key (`main.rs:962`); no AMQP-less profile is documented |
| G-9 | Verifiable credentials (OID4VCI / OID4VP) | Pv / Ex | — | — | K P2 | **P2 (design only)** | Nothing |
| G-10 | Benchmark currency: Keycloak 26.8 memory claim; authentik never measured | — | — | — | K §4.1, A §4 | **P2** | `benchmarks/targets/` has `axiam`, `keycloak`, `zitadel`; run 5 measured Keycloak 26.7.0 |
| G-11 | RADIUS interface | — | — | GA (EAP-TLS Ent) | A P2 | **P3 (spike)** | Nothing |
| G-12 | Front-channel logout | GA | ? | GA | K P3, A P3 | **P3 (decline, recorded)** | RP-initiated and back-channel logout shipped (B5) |
| G-13 | Social-provider presets | large catalogue | GitLab, Azure AD, Zitadel | large catalogue | K P3 | **P3 (on demand)** | Google, GitHub, Microsoft, Apple, generic OIDC/OAuth2 |
| G-14 | Hosted offering, admin-console breadth, flow designer, outposts (proxy, RAC), governance workflows | varies | cloud | GA / Ent | K P3, Z P2, A P3 | **Watch, do not chase** | Out of the API-first scope by the comparisons' own argument |
| G-15 | Agent identity positioning (`zitadel/nextgen`, authentik "agent accounts") | — | Pv | Ent | Z P3, A table | **Watch + documentation** | Service accounts, RFC 8693 delegation with `act`, MCP profile end to end |

**Closed, not gaps.** Deny-override, device grant, token exchange (internal and
external), SCIM inbound, the logout and PAR triad, UMA 2.0, WebAuthn
attestation policy, DPoP, mTLS client auth, CIMD, RFC 8707, RFC 7591 and the
MCP profile all appear as parity or advantage in the three tables. Nothing in
this plan reopens them.

---

## 3. Ranking rationale

**Why G-1, G-2 and G-3 are the only P1s.** All three comparisons name the same
three items in their P1 tier, and each one blocks a *procurement* step rather
than a technical one. Certification is the checkbox buyers tick before any
evaluation. SAML issuance is the integration that enterprise SaaS still
demands, and AXIAM is the only one of the four products that cannot do it.
Directory federation is the brownfield door: without it AXIAM can replace a
greenfield IAM but cannot sit in front of an existing one. Their order matters
too: G-1 is nearly free (the work is reading four `REVIEW` logs and sending a
submission), G-2 reuses a 3 500-line SAML stack that already parses, verifies
and signs, and G-3 is the only P1 that starts from nothing.

**Why G-4 ranks above the other P2s.** It is small, it extends a surface AXIAM
markets (MCP clients register dynamically and increasingly expect to update or
delete their registration), and `dcr.rs` already names it as deferred.

**Why G-5 and G-6 are kept together.** Both are *outbound* identity signals.
SSF pushes session and credential events to relying parties; outbound SCIM
pushes lifecycle events to applications. They share a delivery engine (the
webhook dispatcher's retry, backoff and signing) and the same source of truth
(the audit and revocation feeds). Designing them apart would build two
dispatchers.

**Why G-8 is in the plan at all.** The Zitadel comparison is honest that the
whole-stack memory cell is the one efficiency figure AXIAM loses. An AMQP-less
profile also removes the single largest operational objection a small
deployment raises ("why do I need a broker for an IAM?"). It is a deployment
profile, not a product change.

**Why G-9 is design only.** OID4VCI is preview and OID4VP experimental in
Keycloak; the EUDI wallet reference framework is still moving. Writing the
design now, and implementing when the specifications settle, is cheaper than
chasing a moving target.

**Why G-12 is declined rather than deferred.** Front-channel logout depends on
third-party iframes and cookies, which browsers are removing. Back-channel
logout, which AXIAM ships, is the robust variant. Recording the decision stops
the item from reappearing in every future comparison.

---

## 4. Remediation items

Each item has the form: *Target · Today · Design · Acceptance · Bookkeeping ·
Size · Model*. Size is in single-session units as the roadmap uses them
(S ≤ 1, M 2–3, L 4–6, XL > 6). The model column names the cheapest model that
is adequate, between Claude Opus 5.5 (`claude-opus-5-5`, $4 / $20 per million
input / output tokens) and Claude Sonnet 5.5 (`claude-sonnet-5-5`, $2 / $10):
Opus 5.5 costs exactly twice Sonnet 5.5, so it is used only where a mistake is
a CVE, a normative contract change or a cross-crate design decision, and
Sonnet 5.5 everywhere a plan, a specification or an external oracle (the
conformance suite, an existing test) pins the behaviour. §6 breaks every item
into tasks and assigns the model per task.

### G-1 — Certification: Basic OP and FAPI 2.0 submissions — **P1**

> **EXECUTED (partly) — G-1, W1: T23.1.1 – T23.1.3, 2026-10-02 / 03.** The
> premise of *Today* was wrong, and the wave started by correcting it: X7.1
> to X7.3 had **already shipped** in an earlier phase (the gates and
> `AuthnRequestParams` in `crates/axiam-oauth2/src/authn_params.rs` and
> `fapi.rs`, the session evidence as schema **v55/v56**, not v50, the
> `axiam_op_session` cookie and `login_hop.rs`, the SPA's `returnTo.ts`), and
> so had most of X7.4 to X7.9: the 2026-09-25 Basic OP run already passes
> `oidcc-prompt-none-logged-in`, `oidcc-max-age-10000` and `oidcc-id-token-hint`.
> `extra-B-track-features.md` §X7 and `basic-op-gap-plan.md`'s status line
> still say "plan only". The three W1 tasks were therefore run as independent
> audits of the shipped code against its specification, on the model §6
> assigns, closing every gap with tests. They found **five defects**, all
> fixed with a test that failed first:
>
> - **T23.1.1** (`2552b05`, `3b9b8f6`). Matrix M1–M10 and pins P1/P2 tabulated
>   test by test. (1) A `fapi2` client's `claims.id_token.acr` was silently
>   dropped: `claims` had left the refused list when its `userinfo` member
>   became honoured, and took the `id_token.acr` member with it; it is now
>   security-bearing exactly when it asks for `id_token.acr` or cannot be
>   read. (2) A request object pushed to PAR was ignored (`201`) where the
>   authorization endpoint refuses it; PAR now answers `request_not_supported`.
>   Both amend T-239; `sdks/openapi.json` gains the refused member. Added the
>   missing rows: the pushed carrier over HTTP, a `fapi2` row edited to
>   `honour` refused at authorize, repeated parameters, M9's Basic header on a
>   strong client at five endpoints, DCR and CIMD unable to opt into the
>   honour lane or the hop, and the decode failing closed.
> - **T23.1.2** (`b613727`, `b578270`, `43bb706`). Every session-creation
>   path's `amr` pinned (OPAQUE, TOTP, forced enrolment, both WebAuthn
>   ceremonies, the federation handoff). Two escalations, decided as **D-9**
>   and **D-10** (§8): (3) a refreshed honour-lane ID token lost
>   `auth_time`/`acr`/`amr` after the first browser-session rotation, because
>   the refresh grant re-read a session row rotation had deleted; the evidence
>   is now snapshotted on the OAuth2 refresh token (schema **v68**), amending
>   T-240. (4) A federated IdP asserting a future authentication instant kept
>   a session fresh for `max_age` indefinitely; `authenticated_at` is now
>   `min(upstream, verification instant)`, with a `warn` beyond the existing
>   60 s skew allowance (now the named constant `CLOCK_SKEW_LEEWAY_SECS`),
>   amending T-240.
> - **T23.1.3** (`d965417`, `2fc4771`, `e3c9b65`). The `return_to` validator
>   held: a 56-candidate hostile list (scheme-relative, backslash, encoded
>   slashes, traversal, control characters, look-alikes, over-long, repeated)
>   is refused row for row on the server and in the SPA. (5) A **locked,
>   deactivated or removed account's OP cookie kept buying authorization
>   codes** for the session's lifetime: an account-status change revokes no
>   session, and `/oauth2/authorize` was the one place a session became a
>   principal without re-reading the account. It now applies the refresh
>   path's rule (`AuthService::check_session_holder`), amending T-237 and
>   T-238. (The F4 review then found that this refused every federated user a
>   day after provisioning, since federated accounts are `PendingVerification`
>   for life (T-160), and narrowed it to `account_may_act`, P23W1-03.) Added: session fixation, cross-tenant and cross-user cookie use,
>   no cookie from a password step that still owes a factor, `POST
>   /oauth2/authorize` unrouted, nothing reflected, the decline arm's
>   delivery rule, and M7's end-to-end half.
>
> No contract change, as the bookkeeping line said. What the plan did not
> anticipate, beyond the stale premise: browser SSO cannot work on a T21.6
> per-tenant issuer path, because the cookie's `Path=/oauth2/authorize` is
> not a prefix of `/t/{tenant}/oauth2/authorize` (it fails closed, as
> `login_required`) — open as **D-11**, and G-2 depends on it; an essential
> `claims.id_token.auth_time` on `fapi2` is still dropped — open as **D-12**.
> W2's T23.1.4 and T23.1.5 are expected to be audits too, since X7.4 to X7.8
> are in the tree; T23.1.6 and T23.1.7 (judgements, submission) are not.
>
> **EXECUTED (partly) — G-1, W2: T23.1.4, T23.1.6, T23.1.7, 2026-10-03.** On
> `claude/phase23-w2`. G-1 stays open: the maintainer runs both suites
> personally before the release tag (decision of 2026-10-03), and sends the
> submission; issue #513 closes on the grant, not on this wave.
>
> - **T23.1.4** (`1218dbe`, `9799f87`, `3da0cc0`; Sonnet 5.5). An audit, as
>   expected: every X7.4–X7.6 requirement (`prompt` in its four values and its
>   `none` combinations, `max_age`, `id_token_hint`, ACR derivation and the
>   essential-unmet refusal, the cosmetic four, POST userinfo, and the ignore
>   and `fapi2` twins of each) is tabulated against a named test. No defect in
>   the shipped lane; the rows pinned only at unit level are now pinned over
>   HTTP too (`id_token_hint` wrong subject, wrong client, foreign key, access
>   token, garbage and expired-but-signed; `select_account`; an essential
>   `claims.id_token.acr` on the ignore lane; a non-form body at POST
>   userinfo). **D-12** shipped: an essential (or unreadable)
>   `claims.id_token.auth_time` on `fapi2` is `invalid_request` on both
>   carriers, a voluntary one unchanged, the honour lane still honours it;
>   amends T-239 in all three artifacts, OpenAPI's discovery description
>   regenerated. The audit raised one question the plan had pinned the wrong
>   way, decided as **D-14**: `max_age=0` could never yield a code (`0 >= 0` on
>   the return leg), against OIDC Core §3.1.2.1's errata note that it equals
>   `prompt=login`. It now takes the `prompt=login` path and no path of its own
>   (a unit test proves the two outcomes equal at every age, leg and session
>   state); `prompt=none` with `max_age=0` is `login_required`; test failed
>   first; T-239 amended again. Also corrected: the "plan only" status lines of
>   `extra-B-track-features.md` §X7 and `basic-op-gap-plan.md`, and every
>   statement that discovery publishes `claims_parameter_supported: false`
>   (it publishes `true`).
> - **T23.1.6** (`6f1385b`, `cfb6fcf`, `f3dbea7`, `9c74955`; Sonnet 5.5).
>   [`docs/conformance/REVIEW-JUDGEMENTS.md`](../docs/conformance/REVIEW-JUDGEMENTS.md)
>   with the four Basic OP entries, each citing its 2026-09-25 log id and the
>   screenshot it rests on, each marked *proposed* until the maintainer's run
>   confirms it; nothing in it is a result of a run that was not made. Harness:
>   `report.py` now names every `SKIPPED` module (it counted them and named
>   none, so "PASSED or documented SKIPPED" could not be checked) and keeps the
>   earlier dated reports in `index.md`; `export-evidence.py` (and `just
>   conformance-evidence`) scripts the evidence export the three earlier
>   directories were made by hand. A *maintainer run checklist* in
>   [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md).
> - **T23.1.7** (`9f5fe95`, `47b856b`, `ac87a72`, `58bacf0`, `ee3bac0`;
>   Sonnet 5.5). The three FAPI entries over all three variants, the FAPI half
>   of the checklist (with F4 item (g): rerun
>   `test-claims-parameter-identity-claims` and read its request for `acr` and
>   `auth_time`), and the X5.3 package at the end of
>   [`fapi-certification-submission.md`](fapi-certification-submission.md):
>   what is submitted, every run-dependent field as a placeholder, what to
>   attach and never attach, a pre-send checklist, and the website wording for
>   the mark, kept there and **not** in `website/src/` until the mark is
>   granted. Nothing was sent.
>
> What the plan did not anticipate. The claims `WARNING` is on **all three**
> FAPI variants, every run since 2026-09-10, not on `private_key_jwt` only;
> and it is **not** the "claims not supported" deviation §4 *Design* item 2
> hoped for, since discovery says `true`, so its cause is in the suite log and
> the entry stays *open* until the maintainer's run. The plan's "four FAPI
> variants" are three plan files; the fourth is the Basic plan. `REVIEW` is a
> terminal verdict by the suite's design, so "every module `PASSED`" cannot be
> met literally; the expected shape is the baseline's, each `REVIEW` closed by
> its judgement. And a `require_par` client's unpushed request from an
> anonymous browser goes through the login hop before it is refused (found by
> reading the code, carried to the F4 review). Questions for the maintainer
> are in the W2 PR.

**Target.** Two certificates: OpenID Connect *Basic OP* and *FAPI 2.0 Security
Profile (Final)*, as OpenID Provider, with the results published under
`docs/conformance/` green and red alike, as X5.4's fee-waiver letter promises.

**Today.** The 2026-09-25 runs leave seven modules open, none of them a
`FAILED`:

| Plan | Module | Verdict |
|---|---|---|
| Basic OP | `oidcc-prompt-login` | `REVIEW` |
| Basic OP | `oidcc-max-age-1` | `REVIEW` |
| Basic OP | `oidcc-ensure-registered-redirect-uri` | `REVIEW` |
| Basic OP | `oidcc-ensure-request-object-with-redirect-uri` | `REVIEW` |
| FAPI 2.0 (all three variants) | `…-ensure-unsigned-authorization-request-without-using-par-fails` | `REVIEW` |
| FAPI 2.0 (all three variants) | `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `REVIEW` |
| FAPI 2.0 (private_key_jwt) | `…-test-claims-parameter-identity-claims` | `WARNING` |

The two Basic OP `prompt`/`max_age` modules are exactly the ones
[`basic-op-gap-plan.md`](basic-op-gap-plan.md) says are unreachable until the
browser-SSO login hop and the `SameSite=Lax` OP-session cookie exist (X7.2,
X7.3). The plan is complete and the maintainer answered its two escalations on
2026-09-07; no crate source has changed since.

**Design.** No new design: execute X7.1 through X7.9 as planned, then X5.3.
Two additions:

1. A `REVIEW` module is closed by a human reading the suite log and writing
   the judgement down. Add `docs/conformance/REVIEW-JUDGEMENTS.md`, one entry
   per module: the log id, what the suite could not decide, what AXIAM does,
   and why that is conformant. A certification submission is this file plus
   the green run.
2. The `WARNING` on the `claims` parameter asks whether AXIAM honours
   requested identity claims on the FAPI lane. R-2 (requested claims survive a
   refresh) already touched this path; verify the warning is the "claims
   parameter not supported" deviation that FAPI permits and record it in the
   same judgement file, or support it on the honour lane only.

**Acceptance.** Both plans run `PASSED` on every module except documented
`SKIPPED` ones; the four FAPI variants are identical to the 2026-09-25
baseline except for the three modules above; the submission is sent and the
mark published on the website once granted.

**Bookkeeping.** `docs/conformance/`, the website's security section
(`website/src/docs/`), the threat model entries X7 names (profile-confusion
matrix M1–M9), `CHANGELOG.md`. No contract change: X7.0 decision A needs no
SDK code change.

**Size.** L (X7 is nine waves, several of them small). **Model.** Opus 5.5 for
X7.1 to X7.3 (authorization-request gating and the OP cookie are
security-bearing); Sonnet 5.5 for the harness, judgements and submission.

### G-2 — SAML 2.0 identity provider — **P1**

**Target.** AXIAM issues SAML 2.0 assertions to registered service providers,
per tenant: IdP metadata, Web Browser SSO profile with HTTP-Redirect and
HTTP-POST bindings, SP-initiated and IdP-initiated flows, signed assertions
(and optionally signed responses), attribute mapping from AXIAM claims, and
single logout wired into the existing session-revocation path.

**Today.** `crates/axiam-federation/src/saml.rs` implements the SP side on
`samael` with `xmlsec`: it builds `AuthnRequest`s, verifies signed responses
and assertions and maps claims. Everything an IdP needs to *verify* is there;
everything it needs to *issue* (assertion construction, signing with a tenant
key, SP registry, SLO) is not. The whole SAML stack is behind the `saml`
feature because `libxml` needs system libxml2 headers.

**Design.**

- **Placement.** A new module `saml_idp` in `axiam-federation` (layer 3) for
  the protocol, and a new `SamlServiceProvider` model in `axiam-core` with a
  repository in `axiam-db`. Routes live in `axiam-api-rest` under
  `/saml/v2/{tenant}/metadata`, `/sso`, `/slo`, mirroring the per-tenant
  path issuers T21.6 introduced for OIDC. No new crate: the layering table
  stays as it is.
- **Signing key.** The IdP signing certificate is issued by the tenant's
  signing CA through `axiam-pki`, with a new `CertificateType::SamlSigning`
  that reuses T22.14's per-type KU/EKU profile (digitalSignature only, no
  SANs). The private key is stored encrypted at rest exactly as signing-CA
  keys are (AES-256-GCM, `ca_key_store.rs`). This is the one place AXIAM is
  structurally ahead: Keycloak, Zitadel and authentik all require an
  externally produced certificate.
- **SP registry.** `SamlServiceProvider { tenant_id, entity_id, acs_urls,
  slo_url, name_id_format, sign_assertions, sign_responses, encrypt_assertions,
  sp_signing_cert, attribute_mappings, allowed_groups }`. Metadata import
  (upload an SP metadata XML) and manual entry. The ACS URL list is an
  allow-list checked the way redirect URIs are (exact match, no globs).
- **Authentication.** The SSO endpoint reuses X7.3's browser login hop and
  OP-session cookie: a SAML `AuthnRequest` is an authorization request with a
  different wire format. `ForceAuthn` maps to `prompt=login`; `IsPassive` to
  `prompt=none`. MFA enforcement, OPAQUE and passkeys apply unchanged because
  the session is the same session.
- **Assertion contents.** `NameID` from a per-SP policy (persistent pairwise
  identifier by default, email on request), `AuthnContextClassRef` from the
  session's `amr`, attributes from a mapping table over user fields, groups
  and roles. `SessionIndex` is the AXIAM session id, so SLO and the
  revocation feed revoke the same thing.
- **Security rules.** Assertions are signed always; responses signed by
  policy; `NotOnOrAfter` five minutes; `InResponseTo` must match an
  outstanding request stored with the same single-use guarantee X6 built for
  authorization codes; `Destination` must equal the ACS URL used; encryption
  with the SP's certificate optional and off by default. XML parsing stays in
  `samael`/`libxml` with external entities disabled, which the SP side
  already enforces.
- **Feature flag.** Same `saml` feature as the SP. The admin console gains an
  *SAML Service Providers* page per tenant.

**Acceptance.** An end-to-end test with a reference SP (the `samael`
test SP, plus an exported metadata round trip against Keycloak's SAML client
in the e2e harness); SP-initiated and IdP-initiated login; SLO revokes the
session and the revocation feed shows it; a replayed `InResponseTo` is
refused; an ACS URL outside the registry is refused; a tenant without the
feature returns 404 on all three endpoints.

**Bookkeeping.** Contract: a new §29 *SAML service provider registration*
for the eleven SDKs (management CRUD only; no SDK runs the browser flow).
OpenAPI regenerated. Threat model: new elements for the SSO and SLO endpoints
and the SP registry; threats for assertion replay, ACS redirection, signing
key exposure, XML external entities. Website: *Integrate* section. Design
document: the federation chapter.

**Size.** XL. **Model.** Opus 5.5 for assertion issuance, signing and the SP
allow-list; Sonnet 5.5 for the SP CRUD, metadata import, console page and SDK
fan-out.

### G-3 — LDAP / Active Directory identity source — **P1**

**Target.** A tenant can federate an existing LDAP or Active Directory
directory: users authenticate with their directory password, are provisioned
just in time, and their directory groups map onto AXIAM groups, so roles and
permissions keep working. Read-only against the directory. Kerberos is out of
scope for this item (see *Decisions*).

**Today.** Nothing in the tree. The design document does not mention
directories. The closest ancestors are the federation configuration model
(per-tenant external IdP with encrypted secrets, T19.8) and SCIM inbound
provisioning (user and group reconciliation with external ids).

**Design.**

- **Placement.** A new crate `axiam-directory` at **layer 3** next to
  `axiam-federation` (it is a federation protocol, with the same dependency
  shape), added to the layering table in `scripts/check-crate-layering.py`
  and to [`crate-layering.md`](crate-layering.md) in the same commit. It is a
  new crate, so it opts into `missing_docs` from its first commit. Dependency:
  the `ldap3` crate over `rustls` (no OpenSSL; the workspace is
  `rustls`-only).
- **Model.** `DirectoryConfig { tenant_id, url (ldaps:// or ldap:// +
  StartTLS, plaintext refused), bind_dn, bind_secret (secret provider, R-5
  pattern), base_dn, user_filter, user_attribute_map, group_base_dn,
  group_filter, group_member_attribute, sync_interval, jit_provisioning,
  trust_anchors }`. One directory per tenant in the first cut.
- **Authentication.** A new credential path in `axiam-auth`: resolve the
  user's DN by filter, bind as the user with the presented password, never
  store the password or a hash. The directory decides; AXIAM's brute-force
  counters, rate limits and lockout still apply in front of it, since the
  directory's own lockout policy may be absent. On success, upsert the local
  user with `source = directory`, `external_id = entryUUID | objectGUID`.
  MFA, passkeys and session issuance then proceed as for any user.
  Password change, reset and OPAQUE are refused for directory users with a
  clear error.
- **Group mapping.** `memberOf` (AD) or reverse `member` lookup (OpenLDAP),
  nested groups resolved to a configurable depth; mapped to AXIAM groups by
  DN or by a mapping table, so role inheritance through groups is unchanged.
- **Sync.** A background job on the server's existing cleanup-interval
  scheduler, per tenant: incremental by `modifyTimestamp` /
  `uSNChanged`, full reconciliation nightly, soft-delete on disappearance
  (never hard delete; GDPR erasure stays an explicit admin action).
- **Security rules.** Filters built with RFC 4515 escaping only, never by
  string formatting; referrals not followed; TLS verification mandatory with
  per-tenant trust anchors (the org CA can be one); bind secret via the
  secret provider; the bind DN gets read-only directory rights and the docs
  say so; connection pool bounded per tenant.

**Acceptance.** Integration tests against containerised OpenLDAP and Samba AD
in the e2e harness (`docker/` gains both): login, JIT provisioning, group
mapping into an existing role assignment, nested group, disabled directory
account refused, filter injection attempt refused, plaintext URL refused at
config time, sync removes a vanished user as soft-delete.

**Bookkeeping.** Contract: no SDK change for login (the SDK calls the same
login endpoint); a §30 management CRUD for the directory config. OpenAPI,
console page (*Directory* per tenant), website *Integrate* section, design
document chapter, threat model elements for the directory connector and the
sync job.

**Size.** XL. **Model.** Opus 5.5 for the bind path, filter construction and
trust handling; Sonnet 5.5 for sync, mapping, CRUD, console and docs.

### G-4 — RFC 7592 client configuration endpoint — **P2**

> **EXECUTED — G-4 (T23.4.1), 2026-10-03.** `aa67315`, `ec50001`, `20ab11b`.
> `POST /oauth2/register` now returns, once, a `registration_access_token` (32
> CSPRNG bytes, base64url; only its SHA-256 is stored, on the client row,
> schema **v69**) and a `registration_client_uri` built from the same issuer
> the registration used (bare under `/t/{tenant_id}`, `?tenant_id=` at the
> root). `GET`, `PUT` and `DELETE /oauth2/register/{client_id}` authenticate
> by that token in the `Authorization` header only, compared as a digest in
> one `WHERE` with the tenant, the path's `client_id` and `managed_by = 'dcr'`.
> Unknown client, wrong token, another tenant and a client that has no token
> (admin-created, CIMD, DCR before v69) are one indistinguishable `401
> invalid_token`; a token in the query string is `400`. `PUT` is RFC 7592's
> full replacement, re-validated by the same `dcr::validate` under the
> tenant's current policy, written through a type that holds only what a
> registration may set (profile, X7 flags, provenance and tenant are
> untouchable by construction), and rotates the token as one compare-and-swap
> on X6's two layers: of four racing `PUT`s, one wins. `DELETE` revokes the
> client's refresh tokens and frees its `dcr_max_clients` slot (#471). The
> three routes share one bucket at the registration preset (§7 rule 6), and
> every call is audited without the token or its digest.
>
> Tests: thirteen `rfc7592_*` integration tests in
> `dynamic_registration_test.rs` covering every acceptance point (round trip,
> foreign and wrong credentials, widening refused, rotation, the race, refresh
> revocation, quota release, token-less clients, cross-tenant, the limiter,
> redaction, a tenant that disabled registration); the T21.8 MCP harness now
> reads, restates and deletes its registration in both issuer modes; eight
> unit tests in `dcr.rs` and four in the repository.
>
> Contract **1.53**: §28.12 adds `read_client_registration`,
> `update_client_registration` and `delete_client_registration`, with
> `registration_access_token` `Sensitive<T>` from the first day (the #480
> lesson), no retry of `PUT` or `DELETE`, and five portable tests; §28.0's
> "no network I/O" sentence is rescoped to §28.1–§28.11. OpenAPI and the
> management registry regenerated. Threat **T-289** (model 2.18.0, 289
> threats, 276 mitigated). Website *OAuth2* section, the DCR admin guide,
> `docs/api/mcp.md`, the *Identity for agents* guide and the `b7-mcp-server`
> example updated.
>
> What the plan did not anticipate. `DELETE` does **not** revoke the users'
> AXIAM sessions, though *Design* said "tokens and sessions": a session
> belongs to the user, not to the client, and letting a client's holder end
> other people's sessions would be a new denial-of-service. It revokes what
> the client holds; access tokens live to their 15-minute `exp`. `GET` never
> returns the token again, which RFC 7592 §3 calls REQUIRED in the response:
> only a digest is stored. The admin `DELETE /api/v1/oauth2-clients/{id}`
> revokes nothing, so the self-service path now does strictly more than the
> admin one — recorded for a follow-up. And a bare `web::Path<String>` 404s
> under `/t/{tenant_id}`; only the MCP harness's path-issuer run caught it.

**Target.** A dynamically registered client can read, update and delete its own
registration with the `registration_access_token` RFC 7591 lets the server
return.

**Today.** `dcr.rs` issues registrations and deliberately omits
`registration_access_token` and `registration_client_uri`, recording RFC 7592
as deferred. The `oauth2_registration_token` model holds *initial access*
tokens for gated registration, not per-client management tokens.

**Design.** On `POST /oauth2/register`, mint a per-client management token
(32 random bytes, hash stored on the client row, plaintext returned once) and
return `registration_client_uri = {issuer}/oauth2/register/{client_id}`.
Mount `GET`, `PUT`, `DELETE` on that URI, authenticated by the management
token only (never by a user or service-account token), tenant-scoped through
the issuer path. `PUT` re-validates through the same `validate` as
registration, keeps the tenant's policy limits, and rotates the management
token. `DELETE` revokes the client's tokens and sessions through the existing
revocation path. Rate limit the three routes with the registration limiter.

**Acceptance.** Round trip register → read → update redirect URIs → delete;
a token from another client is `401`; a `PUT` widening scopes beyond tenant
policy is `400`; the MCP e2e harness (T21.8) exercises read and delete.

**Bookkeeping.** Contract §28 (MCP helpers) gains the three operations;
OpenAPI; threat model entry on the management token; website *OAuth2*
section.

**Size.** S. **Model.** Opus 5.5 (an unauthenticated-by-user write surface on
the authorization server, the same class as T-272 to T-280).

### G-5 — Shared Signals Framework transmitter — **P2**

**Target.** AXIAM transmits CAEP `session-revoked`,
`credential-change`, `assurance-level-change` and RISC `account-disabled`,
`account-enabled`, `account-purged` events as Security Event Tokens (RFC
8417) to registered receivers, over push (RFC 8935) and poll (RFC 8936), with
the SSF stream management API and discovery at
`/.well-known/ssf-configuration`.

**Today.** The ingredients exist and the protocol does not. The revocation
feed (`GET /oauth2/revocations`, R-6) already publishes session and token
revocations; webhooks deliver HMAC-signed JSON with retry; Reactors emit the
same events onto AMQP; the audit log records credential changes.

> **Orchestrator note, 2026-10-02 (from T23.9.1).** There is no per-tenant
> signing key: AXIAM signs with **one Ed25519 key per deployment**
> (`crates/axiam-auth/src/config.rs`, `AuthConfig::jwt_private_key_pem`), and
> the per-tenant `jwks_uri` serves that same key. "The tenant's EdDSA issuer
> key" below therefore means the deployment key published at the tenant's
> JWKS URL, unless D-13 decides otherwise before T23.5.2 starts.

**Design.** A `ssf` module in `axiam-oauth2` (layer 4): a `SsfStream` model
per tenant and receiver (audience, delivery method, endpoint, requested
events, status), SETs signed with the tenant's EdDSA issuer key and published
on the existing JWKS, a subject identifier policy (`iss_sub` by default,
`email` on request). Event sources: the revocation feed for sessions and
tokens, the audit log for credential and account state changes. Delivery
reuses the webhook dispatcher's queue, retry and backoff; poll delivery is a
per-stream bounded buffer with acknowledgement. Receiver registration is an
admin operation; the stream management API is receiver-authenticated by an
OAuth2 client credential with a dedicated scope.

**Acceptance.** A test receiver in the e2e harness receives a SET within one
second of a session revocation and verifies it against the JWKS; poll with
acknowledgement drains the buffer; a disabled stream delivers nothing;
discovery lists the supported events.

**Bookkeeping.** Contract: a receiver helper is optional (`SHOULD`) in the
seven full-surface SDKs. Threat model: new element and threats for receiver
impersonation and event flooding. Website *Integrate* section.

**Size.** L. **Model.** Opus 5.5 for SET issuance and stream authentication;
Sonnet 5.5 for delivery plumbing and docs.

### G-6 — Outbound SCIM provisioning — **P2**

**Target.** A tenant can register downstream SCIM 2.0 service providers and
AXIAM pushes user and group lifecycle changes to them, with reconciliation.

**Today.** `axiam-scim` is a server only. User and group mutations already
produce audit events and webhook deliveries.

**Design.** A SCIM client in `axiam-scim` (layer 7 already; the client needs
nothing from the REST layer, so it can move to layer 3 if the layering check
prefers, in the same commit that adds the code). `ScimTarget { tenant_id,
base_url, auth (bearer via secret provider | OAuth2 client credentials),
mapping, filter (groups whose members are provisioned) }`. Lifecycle events
from the same source as G-5 are translated to `POST /Users`, `PATCH`, and
`DELETE` (or `active=false` by policy), with `externalId = AXIAM id` and the
downstream id stored on a link row. Delivery through the shared dispatcher
(G-5). A nightly reconciliation lists the downstream and repairs drift.

**Acceptance.** A test SCIM server in the harness; create, rename, group
membership change, disable and erase propagate; a downstream 5xx retries with
backoff and a 4xx dead-letters with an admin notification; GDPR erasure
(T18.2) propagates as `DELETE`.

**Bookkeeping.** Contract §31 management CRUD; OpenAPI; console page; threat
model (credential storage for targets, over-provisioning); website.

**Size.** M. **Model.** Sonnet 5.5, with the dispatcher shared with G-5 built
first under Opus 5.

### G-7 — CIBA — **P2**

**Target.** OpenID Connect Client-Initiated Backchannel Authentication, poll
and ping modes, as the FAPI-CIBA profile requires.

**Today.** Nothing. The device grant (B2) is the nearest relative: a pending
authorization that a user completes elsewhere.

**Design.** `POST /oauth2/bc-authorize` issues an `auth_req_id` bound to a
`login_hint` or `id_token_hint`, with `binding_message` and a user code; the
user is notified through the email service (and later push) and approves on
the user identity pages (T15.7) after full authentication including MFA; the
token endpoint accepts `grant_type=urn:openid:params:grant-type:ciba` with
the same single-use redemption X6 guarantees. Ping mode reuses the webhook
dispatcher. Brute-force protection on `auth_req_id` polling: interval
back-off, as the device grant does, and the rate-limit preset.

**Acceptance.** Poll and ping end to end in the e2e harness; expired and
already-redeemed requests refused; the Keycloak CVE class (brute-force
lockout not applying to CIBA, 26.7.x) covered by a test that the limiter
counts CIBA attempts.

**Bookkeeping.** Contract §32 (the seven full-surface SDKs gain a CIBA
initiation helper); OpenAPI; threat model; website.

**Size.** L. **Model.** Opus 5.

### G-8 — AMQP-less deployment profile and whole-stack footprint — **P2**

**Target.** A documented *minimal* profile in which AXIAM runs with SurrealDB
only, and a re-measured whole-stack resting footprint.

**Today.** The broker is mandatory: `axiam-server` fails closed at boot
without an AMQP signing key (SECHRD-08), and async authz, audit ingestion,
mail delivery, Reactors, event notifications and the cross-replica
cache-invalidation publisher all ride AMQP.

**Design.** `AXIAM__AMQP__ENABLED=false` (default `true`): the AMQP consumers
and producers are not started; audit events are written directly by the audit
service (which already has the repository); the mail consumer runs in-process
on a bounded channel; webhooks already deliver from the REST process;
Reactors and async authz are reported as unavailable in `/health` and their
admin routes return `409` with a message naming the profile. Cross-replica
cache invalidation has no transport without the broker, so the minimal
profile is **single-replica by definition**: boot refuses `amqp.enabled=false`
together with a replica count above one, and the docs say so first. The compose
file gains `docker-compose.minimal.yml`. The benchmark's §5 resource table
gains a *minimal* row.

**Acceptance.** The full REST and gRPC suites pass with the flag off, minus
the Reactor and AMQP tests, which are skipped by profile and listed; boot
refuses a configuration that enables Reactors with AMQP off; the resting RSS
of server plus SurrealDB is measured and published.

**Bookkeeping.** Deployment docs, website *Operate*, `CHANGELOG`, benchmark
analysis. No contract change.

**Size.** M. **Model.** Sonnet 5.5, with an Opus 5.5 review of the audit-write
path (audit durability, T19.27, must not regress).

### G-9 — Verifiable credentials: design only — **P2**

> **EXECUTED — G-9 (T23.9.1), 2026-10-02.** [`verifiable-credentials-design.md`](verifiable-credentials-design.md)
> is written, design only: no crate, schema, route, contract section or
> threat-model entry accompanies it. It meets the four acceptance points:
> **specification versions** (§2: OID4VCI 1.0, OID4VP 1.0 and HAIP 1.0 Final,
> SD-JWT as RFC 9901, SD-JWT VC and Token Status List as the draft revisions
> HAIP pins, ISO/IEC 18013-5/-7, ARF `v3.0.0`, each with how it was verified
> and §16 listing what could not be); **crates evaluated** (§9); **threat-model
> elements** E1–E8 and a new wallet ↔ AXIAM trust boundary, named but
> deliberately not entered (§10); and a **go/no-go** criterion (§13:
> specification stability *and* one concrete adopter, with a partial go and
> re-evaluation triggers).
>
> Its recommendations: verifier before issuer, because the eIDAS 2 obligation
> falls on relying parties; SD-JWT VC only, mdoc deferred to an mDL adopter,
> W3C VCDM declined; a new `axiam-vc` crate at layer 5 behind a `vc` feature,
> off by default; `scope` rather than RFC 9396 in the first cut; status through
> a per-tenant Token Status List kept apart from the session-revocation feed.
> Cost: XL for each role (about 18–27 sessions for the verifier, 19–29 for the
> issuer). Its proposed decisions VC-D1 … VC-D10 (§14) wait for the phase that
> schedules the work and are not added to §8 here.
>
> What the plan did not anticipate, and what later items must take into
> account: **AXIAM has one Ed25519 signing key per deployment, not one per
> tenant** (`crates/axiam-auth/src/config.rs`, `AuthConfig::jwt_private_key_pem`);
> the per-tenant `jwks_uri` publishes the same key at a per-tenant URL. That
> premise is also in G-5's design ("SETs signed with the tenant's EdDSA issuer
> key") and is recorded there. HAIP requires ES256, which collides with the
> EdDSA-only pin unless credential keys are separate keys, which the design
> makes them. In the EUDI ecosystem the integrated CA cannot be the trust
> anchor (Member State access CAs and trusted lists are), so AXIAM would need
> "generate key → CSR → import an external chain". No JWE exists anywhere in
> the workspace, and a HAIP verifier must decrypt responses (VC-D6).

**Target.** `claude_dev/verifiable-credentials-design.md`: how AXIAM would act
as an OID4VCI issuer and an OID4VP verifier for the EUDI wallet architecture,
which credential formats (SD-JWT VC first, mdoc evaluated), how the tenant
signing keys and the integrated CA map onto issuer trust, what the data model
and endpoints are, and what the implementation would cost. No code.

**Acceptance.** The design names the specification versions it targets, the
Rust crates evaluated, the threat model elements it would add, and a go/no-go
criterion (specification stability, one concrete adopter).

**Size.** S. **Model.** Opus 5.

### G-10 — Benchmark currency — **P2**

**Target.** Re-measure Keycloak at 26.8 (which reports reduced memory) and
Zitadel at v4.19, and add authentik 2026.8 as a fourth benchmark target, so
that the authentik comparison can make a performance statement.

**Design.** A `benchmarks/targets/authentik/` profile in the same shape as
`keycloak/` and `zitadel/` (container, seed, k6 scenarios for the shared
endpoints: client credentials, introspection, JWKS, userinfo, password
login); run 6 on the same G-box with the run-5 caps.

**Acceptance.** `PUBLIC_BENCH_ANALYSIS.md` seventh draft with four targets;
the three comparison documents' performance rows updated and their change
logs dated.

**Size.** M. **Model.** Sonnet 5.

### G-11 — RADIUS: spike — **P3**

**Target.** A one-session spike answering whether a RADIUS front end with
EAP-TLS over the integrated CA is a fit for AXIAM's network-device audience,
and what it would cost. authentik gates EAP-TLS behind its enterprise licence;
AXIAM could ship it open source. Outcome: a decision record, not code.

**Size.** S. **Model.** Sonnet 5.

### G-12 — Front-channel logout: decline — **P3**

> **EXECUTED — G-12 (T23.12.1), 2026-10-02.** The decline is recorded in
> [`design-document.md` §4.5 *Logout*](design-document.md#45-logout), a section
> the document did not have before: it now states what ships (RP-initiated
> logout at `/oauth2/end_session`, back-channel logout with one logout token per
> client, `sid` always present and a 120 s lifetime, and the opt-in revocation
> feed) and, under *Front-channel logout — declined (D-6, 2026-10-02)*, what the
> mechanism is, why it fails silently under ITP, Total Cookie Protection and
> Chrome's third-party-cookie restrictions, what to use instead, and the
> reopen condition (an adopter request, not a comparison). Verified in code
> before writing: discovery (`crates/axiam-oauth2/src/oidc.rs`) advertises
> `backchannel_logout_supported` and `backchannel_logout_session_supported` and
> no `frontchannel_*` field, and the client model carries
> `backchannel_logout_uri` only.
>
> The Keycloak and authentik comparisons flip the §2 row to *declined by
> design* and mark the §3 P3 item declined, with a pointer here; all three
> change logs carry a dated line. The Zitadel comparison has no front-channel
> row or gap-list entry, so only its change log moved, worded to say so.

**Decision.** Not implemented. Rationale: it depends on third-party iframes
and cookies that browsers are removing; back-channel logout (shipped) is the
robust variant and the one FAPI and the OpenID logout certification profile
for back-channel require. Record in the design document's logout chapter and
in the three comparisons' change logs so the item stops recurring. Revisit
only on a concrete adopter request.

**Size.** S (documentation).

### G-13 — Social-provider presets: on demand — **P3**

**Decision.** Generic OIDC and OAuth2 cover the catalogue. Add a named preset
only when a user asks, one preset per PR, GitLab first if any. No scheduled
work.

### G-14 — Portal features: watch, do not chase

Hosted offering, admin-console breadth, visual flow designer, forward-auth
and remote-access outposts, privileged-access and offboarding workflows.
All three comparisons place these outside AXIAM's scope. No work. The
competitor change logs track them.

### G-15 — Agent identity: documentation

> **EXECUTED — G-15 (T23.15.1), 2026-10-02.**
> [`docs/guides/identity-for-agents.md`](../docs/guides/identity-for-agents.md)
> (a new `docs/guides/` directory, indexed from `docs/README.md`) walks one
> agent through registration (service account, confidential client, public
> loopback client, DCR or CIMD, with the grants each may hold and the
> refusals each meets), delegation by RFC 8693 token exchange with `act` and
> the depth-3 cap, resource indicators, the §28 resource-server helpers, and
> revocation. The website gains an *Identity for agents* page in the *OAuth2 &
> OIDC* section, after *Token exchange*; `docSectionsAreComplete()` returns no
> problems, and `npm run build` and `npm run lint` pass.
>
> Every feature claim was grounded in a file before it was written; three
> came out as negatives the plan's *Target* paragraph did not anticipate.
> `may_act` is not implemented anywhere, so the guide says who may exchange is
> decided by the client's grant, scopes and `allowed_resources`. A **public
> client can neither exchange nor call `/oauth2/revoke`**, so a local agent
> holds a direct user token with no `act`. And the **actor token is not bound
> to the exchanging client**: the server checks only that it is a valid
> same-tenant access token. The guide states this in *What AXIAM does not do*,
> and the W1 F4 review rated it Medium and pre-existing (P23W1-06, filed as
> ilpanich/axiam#518).
>
> Not verified: the SDK snippets follow the operation names and parameter
> order `CONTRACT.md` §15 and §28 pin, but the per-language packaging (one
> parameter object in Rust and TypeScript, keyword arguments in Python) could
> not be checked against the SDK repositories, which are outside this
> session's scope. Both pages say the SDK's own reference is authoritative.
> RFC 7592 is deliberately not described; T23.4.1 adds it.

**Target.** AXIAM already has what authentik sells as "agent accounts" and
what `zitadel/nextgen` previews: service accounts, RFC 8693 delegation with
`act` and depth-capped chains, CIMD, RFC 8707, loopback public clients and
the MCP profile. The gap is a named story. Add a website page and a
`docs/` guide, *Identity for agents*, that walks an agent through
registration, delegated acting on behalf of a user, resource indicators and
revocation, with SDK snippets from the §28 helpers. Watch `zitadel/nextgen`
in the Zitadel change log.

**Size.** S. **Model.** Sonnet 5.

---

## 5. Sequencing

Dependencies, then waves. G-1 goes first because it is cheap and because G-2
reuses its browser-SSO login hop. G-5 and G-6 share a dispatcher, so the
dispatcher lands once, under G-5. G-8 is independent and can fill gaps.

```
G-1 (X7 waves, X5 submission) ──► G-2 (SAML IdP reuses the login hop)
G-3 (directory)                   independent, starts in parallel with G-1
G-4 (RFC 7592)                    independent, small
G-5 (SSF) ──► G-6 (outbound SCIM shares the dispatcher)
G-7 (CIBA)                        after G-1 (FAPI baseline must be green first)
G-8 (AMQP-less)                   independent
G-9, G-10, G-11, G-12, G-15       independent, documentation and measurement
```

| Wave | Items | Why together |
|---|---|---|
| W1 | G-1 (X7.1–X7.3), G-4, G-12, G-15, G-9 | The P1 that is nearly free, three small items, and the two decision documents |
| W2 | G-1 (X7.4–X7.9, X5.3 submission package; T23.1.8 per-tenant OP cookie, D-11), G-3 (crate, model, bind path) | Certification closes; the directory crate's security core lands under Opus 5.5; T23.1.8 must be merged before W3, because G-2's SAML SSO reuses the login hop |
| W3 | G-2 (SP registry, signing key, SSO), G-3 (sync, mapping, console) | SAML IdP on top of the login hop; directory completes |
| W4 | G-2 (SLO, console, contract §29), G-5 (dispatcher, SETs, streams) | SAML completes; the outbound signal spine lands |
| W5 | G-6, G-7, G-8 | Outbound SCIM on the dispatcher; CIBA on a green FAPI baseline; the minimal profile |
| W6 | G-10 (run 6 with four targets), G-11 spike, comparison documents refreshed | Measure after the product changed |

Every wave ends with the F4 security review before merge, as Track B
required, and with `cargo clean` between plan steps as `CLAUDE.md` requires.

> **W1 F4, 2026-10-03:** [`security-review-phase23-w1-2026-10-03.md`](security-review-phase23-w1-2026-10-03.md).
> Fifteen findings, no merge blocker after fixes. Fixed on the branch: two
> **High**, both pre-existing siblings of T23.1.3's defect: the OAuth2
> refresh and code grants never re-read the account (P23W1-01), and federated
> sign-in ignored a suspended account (P23W1-04). Also fixed: one Medium
> regression T23.1.3 introduced (P23W1-03) and one Low (P23W1-02, `Bearer`
> case). Filed: three pre-existing Mediums (ilpanich/axiam#517, #518, #519)
> and three Lows (#520); four residuals accepted with reasons.

Proposed roadmap entry: **Phase 23 — Competitor gap closure**, tasks T23.1
through T23.15 mapping one-to-one onto G-1 through G-15, in wave order. This
plan does not edit `roadmap.md`; the phase is added when the maintainer
accepts the plan.

---

## 6. Model assignment per task

**Rule.** Sonnet 5.5 is the default. A task moves to Opus 5.5 only when one of
three conditions holds: (a) a mistake in it is a vulnerability (token or
assertion issuance, authentication paths, allow-lists, a new write surface
reachable without a user session); (b) it writes normative text the eleven SDKs
must implement (a `CONTRACT.md` section) or a threat-model entry; (c) it makes a
cross-crate design decision nobody has pinned yet. Everything else, including
most plumbing, CRUD, console pages, SDK ports, harnesses and documentation, is
Sonnet 5.5, because the behaviour is pinned by this plan, by a specification or
by an external oracle, and a review catches the rest at half the price.

Two consequences of the pricing: Opus 5.5 at **$4 / $20** is exactly **2×**
Sonnet 5.5 at **$2 / $10** per million tokens, and cache reads cost the same
($0.20) on both, so the saving is on fresh tokens only. Opus 5.5 defaults to
`medium` effort and Sonnet 5.5 to `high`; neither needs changing for this work.

Task ids follow the proposed Phase 23 numbering (`T23.<item>.<step>`). The
*oracle* column says what catches a mistake if the cheaper model makes one;
when the oracle is weak, the model is Opus 5.5.

### G-1 — Certification

| Task | Scope | Model | Why this one, and what catches a mistake |
|---|---|---|---|
| T23.1.1 | X7.1: `authn_request_params` and `browser_sso` flags, typed parser on query and PAR carriers, `enforce_authorization_request` rules, profile-confusion matrix M1–M9 | **Opus 5.5** | A wrong gate lets a FAPI client honour `prompt`/`request` parameters it must refuse; the FAPI run only proves it did not get worse, not that the matrix is right |
| T23.1.2 | X7.2: schema v50 (`authenticated_at`, `amr`, `browser_token_hash`), `auth_time`/`acr`/`amr` snapshot on the code | Sonnet 5.5 | Schema and copy-through plumbing pinned field by field in `basic-op-gap-plan.md`; unit tests on the snapshot |
| T23.1.3 | X7.3: `axiam_op_session` cookie, `/login?return_to` hop with same-origin-path validation, `reauth` mode | **Opus 5.5** | Open-redirect and session-fixation surface; the suite does not test the redirect validator |
| T23.1.4 | X7.4–X7.6: honour lane for `prompt`, `max_age`, `id_token_hint`, ACR derivation | Sonnet 5.5 | Behaviour pinned by OIDC Core §3.1.2.1 and by the Basic OP modules, which are the oracle: `oidcc-prompt-login`, `oidcc-max-age-1` fail if it is wrong |
| T23.1.5 | X7.7 sensitive scopes, X7.8 `client_secret_basic` | Sonnet 5.5 | Decision A is taken; RFC 6749 §2.3.1 pins the parsing; existing client-auth tests extend |
| T23.1.6 | X7.9: Basic OP harness, final runs, `docs/conformance/REVIEW-JUDGEMENTS.md` | Sonnet 5.5 | Suite-driven; a judgement is prose over a log the suite produced |
| T23.1.7 | FAPI `WARNING`/`REVIEW` judgements, X5.3 submission package, website mark | Sonnet 5.5 | Prose and packaging; the runs are already green |
| T23.1.8 | D-11: per-tenant-prefix OP-session cookie minted at sign-in; principal resolution on `/t/{tenant_id}/oauth2/authorize` reads it; logout, `end_session` and session revocation clear every cookie the session minted (closes F4 residual P23W1-10); tests incl. the T23.1.3 audit list re-run on the tenant path, cross-tenant refusal, fixation | **Opus 5.5** | Cookie and session-fixation surface, same class as T23.1.3 |

### G-2 — SAML 2.0 identity provider

| Task | Scope | Model | Why |
|---|---|---|---|
| T23.2.1 | `SamlServiceProvider` model, repository, schema migration; `CertificateType::SamlSigning` on T22.14's per-type profile; encrypted key storage via `ca_key_store.rs` | Sonnet 5.5 | Mirrors existing models and an existing certificate-type profile; schema tests and the PKI suite are the oracle |
| T23.2.2 | `saml_idp` module: assertion builder, `NameID` policy, attribute mapping, XML signing, response envelope | **Opus 5.5** | Assertion forgery is account takeover at every SP; no external oracle until T23.2.7 |
| T23.2.3 | SSO endpoint: `AuthnRequest` parsing (Redirect and POST bindings), `InResponseTo` single-use on the X6 arbiter, ACS allow-list, `Destination` check, `ForceAuthn`/`IsPassive` mapping onto the login hop | **Opus 5.5** | Replay and redirection surface; the trickiest integration with T23.1.3 |
| T23.2.4 | SLO endpoint wired to session revocation and the revocation feed | Sonnet 5.5 | Revocation path exists (R-6); the test is "the session is gone" |
| T23.2.5 | IdP metadata endpoint; SP metadata import (XXE off, as the SP side already enforces) | Sonnet 5.5 | `samael` parses; existing SP tests cover the parser hardening |
| T23.2.6 | Admin console *SAML Service Providers* page | Sonnet 5.5 | Console pattern identical to OAuth2 clients |
| T23.2.7 | e2e: `samael` test SP and Keycloak SAML client round trip, replay and bad-ACS refusals, feature-off 404 | Sonnet 5.5 | Writing tests against a pinned acceptance list |
| T23.2.8 | Contract §29, threat-model elements and threats, design-document federation chapter | **Opus 5.5** | Normative text and the trust-boundary entries; S-sized, so the premium is small |
| T23.2.9 | OpenAPI regeneration, website *Integrate* section, eleven SDK ports of §29 | Sonnet 5.5 | Contract-pinned fan-out, as every previous port |

### G-3 — LDAP / Active Directory

| Task | Scope | Model | Why |
|---|---|---|---|
| T23.3.1 | `axiam-directory` crate scaffold at layer 3, layering table and `crate-layering.md`, `missing_docs` opt-in, `DirectoryConfig` model/repo with the secret provider for `bind_secret` | Sonnet 5.5 | Scaffolding against an enforced layering check and an existing secret-provider pattern (R-5) |
| T23.3.2 | LDAP client: `ldap3` over `rustls`, mandatory TLS with per-tenant anchors, RFC 4515 filter escaping, bounded pool, no referrals; bind-as-user path in `axiam-auth` behind the existing brute-force counters; refusal of password change, reset and OPAQUE for directory users | **Opus 5.5** | A filter-injection or a plaintext bind leaks corporate passwords; a reset path left open on a shadow account is a takeover. No oracle before T23.3.6 |
| T23.3.3 | JIT provisioning: upsert with `source = directory`, `external_id = entryUUID \| objectGUID` | Sonnet 5.5 | Follows the SCIM inbound reconciliation pattern; repository tests |
| T23.3.4 | Group mapping (`memberOf`, reverse `member`, nested to depth) onto AXIAM groups | Sonnet 5.5 | Pure mapping over fixtures; role inheritance untouched |
| T23.3.5 | Sync job on the cleanup scheduler: incremental by `modifyTimestamp`/`uSNChanged`, nightly full, soft-delete | Sonnet 5.5 | Reconciliation plumbing; GDPR rule pinned (never hard delete) |
| T23.3.6 | OpenLDAP and Samba AD containers in `docker/`; e2e covering the acceptance list, injection attempt included | Sonnet 5.5 | Tests against a pinned list; this is the oracle for T23.3.2 |
| T23.3.7 | Threat-model elements for the connector and the sync job; contract §30 | **Opus 5.5** | Normative and trust-boundary text; S-sized |
| T23.3.8 | CRUD routes, console *Directory* page, OpenAPI, website, design-document chapter | Sonnet 5.5 | Pattern work |

### G-4 to G-15

| Task | Scope | Model | Why |
|---|---|---|---|
| T23.4.1 | RFC 7592: management token mint and hash, `GET`/`PUT`/`DELETE /oauth2/register/{client_id}`, revalidation, token rotation, revocation on delete, rate limit; contract §28 addition; threat entry | **Opus 5.5** | A write surface authenticated by a server-minted bearer, the T-272 … T-280 class; S-sized, so cheap even on Opus |
| T23.5.1 | Extract the webhook dispatcher (`webhook.rs` queue, retry, backoff) into a shared outbound dispatcher with no behaviour change | Sonnet 5.5 | Refactor under the existing webhook tests |
| T23.5.2 | SSF: `SsfStream` model, SET issuance with the tenant EdDSA key, subject-identifier policy, stream management API authentication, `/.well-known/ssf-configuration` | **Opus 5.5** | A forged or misaddressed SET revokes sessions at relying parties |
| T23.5.3 | Push (RFC 8935) and poll (RFC 8936) delivery on the shared dispatcher, event-source wiring from the revocation feed and the audit log, e2e test receiver | Sonnet 5.5 | Specification-pinned transport over a dispatcher that already retries |
| T23.5.4 | Threat-model entries, website, optional receiver helper in the seven full-surface SDKs | Sonnet 5.5, threat entries **Opus 5.5** | Docs and fan-out; the two threat entries ride the T23.5.2 session |
| T23.6.1 | `ScimTarget` model, repository, credential via secret provider or client credentials | Sonnet 5.5 | Mirrors webhook and federation config models |
| T23.6.2 | Lifecycle-event to SCIM translation (`POST`, `PATCH`, `DELETE`/`active=false`), link rows, delivery on the shared dispatcher | Sonnet 5.5 | RFC 7644 pins the wire; a test SCIM server is the oracle |
| T23.6.3 | Nightly reconciliation, dead-letter with admin notification, GDPR erasure propagation | Sonnet 5.5 | Reconciliation plumbing |
| T23.6.4 | CRUD, console, contract §31, OpenAPI, website, threat entries | Sonnet 5.5 | Management CRUD; the threat entries are "credential at rest for a target", a known pattern |
| T23.7.1 | CIBA: `bc-authorize`, `auth_req_id` lifecycle, grant redemption on the X6 single-use arbiter, polling back-off, rate-limit preset coverage | **Opus 5.5** | A new grant; the Keycloak 26.7 CVE class is exactly a limiter forgetting this grant |
| T23.7.2 | User approval on the identity pages after full authentication, email notification, ping mode on the dispatcher | Sonnet 5.5 | UI and notification plumbing over existing services |
| T23.7.3 | e2e poll and ping, contract §32, SDK initiation helper in the seven full-surface SDKs, website | Sonnet 5.5 | Fan-out |
| T23.8.1 | `AXIAM__AMQP__ENABLED=false`: consumers and producers not started, in-process mail channel, direct audit writes, `/health` and `409` reporting, boot refusals (Reactors on, replicas above one) | Sonnet 5.5 | Configuration plumbing over existing services; the full suite with the flag off is the oracle |
| T23.8.2 | Review of the direct audit-write path against T19.27 durability | **Opus 5.5** | Review only, a fraction of a session; audit loss is a compliance failure |
| T23.8.3 | `docker-compose.minimal.yml`, deployment docs, website *Operate*, resting-RSS measurement and benchmark §5 row | Sonnet 5.5 | Docs and measurement |
| T23.9.1 | `verifiable-credentials-design.md` (OID4VCI issuer, OID4VP verifier, SD-JWT VC, trust mapping, go/no-go) | **Opus 5.5** | Design judgement with nothing pinned; S-sized |
| T23.10.1 | `benchmarks/targets/authentik/` profile in the Keycloak/Zitadel shape | Sonnet 5.5 | Pattern copy |
| T23.10.2 | Run 6 on the G-box, `PUBLIC_BENCH_ANALYSIS.md` seventh draft, comparison rows and change logs | Sonnet 5.5 | Measurement and reporting |
| T23.11.1 | RADIUS / EAP-TLS spike, decision record | Sonnet 5.5 | A spike |
| T23.12.1 | Front-channel logout decision recorded in the design document and the three comparisons | Sonnet 5.5 | Prose |
| T23.15.1 | *Identity for agents* guide and website page with §28 SDK snippets | Sonnet 5.5 | Documentation over shipped features |
| F4 (per wave) | Security review of the wave's diff before merge, threat-model reconciliation | **Opus 5.5** | The one place where a cheaper reviewer is false economy |

**Totals.** 47 tasks: 14 on Opus 5.5 (13 implementation or design tasks plus
the per-wave F4 review), 32 on Sonnet 5.5, and one split (T23.5.4, whose two
threat entries ride the Opus session of T23.5.2). The Opus tasks are deliberately the
small, dense ones (S or the core of an M); the long fan-outs, harnesses and
console pages are all Sonnet. Measured in sessions rather than tasks, roughly a
quarter of the phase runs on Opus 5.5, so the blended cost is about **1.25×** an
all-Sonnet run and about **0.6×** an all-Opus run.

---

## 7. Cross-cutting rules every item owes

1. **Contract before SDK.** A server change that an SDK can see ships with its
   `sdks/CONTRACT.md` section and `sdks/openapi.json` regeneration in the same
   PR; SDK ports follow from the merge commit, never from a draft (the
   fan-out rules in [`remediation-plan-2026-09-12.md`](remediation-plan-2026-09-12.md) §13).
2. **Threat model in the same commit.** New elements and threats enter
   [`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` with the
   code, not after. G-2, G-3, G-5 and G-7 each add a trust boundary.
3. **Layering.** `axiam-directory` is placed in the layering table in the
   commit that creates it; any move of the SCIM client is justified in
   [`crate-layering.md`](crate-layering.md).
4. **Documentation lint.** New crates opt into `missing_docs` from their
   first commit; existing crates are not opted in by these items.
5. **Features.** Everything SAML stays behind the `saml` feature; CI's
   *Build (SAML off)* job must stay green. The directory crate has no
   feature flag (pure Rust, `rustls`).
6. **Safe defaults.** Every new inbound surface (SAML SSO, `bc-authorize`,
   RFC 7592 routes, SSF stream API) is covered by the rate-limit presets
   before merge; a limiter that forgets a route is the Keycloak 26.7 lesson.
7. **Website and comparisons.** Each landed item updates the relevant
   `website/src/docs/` module and flips its row in the three comparison
   tables, with a dated change-log line.

---

## 8. Decisions requested from the maintainer

| # | Question | Recommendation |
|---|---|---|
| D-1 | Kerberos (SPNEGO) in G-3? | **No** in this phase. It needs a browser-facing negotiate handshake and a keytab on the server; LDAP bind covers the directory case. Revisit on request |
| D-2 | SAML assertion encryption in the first cut of G-2? | **Optional and off by default.** Signed assertions over TLS are what the three competitors default to; encryption adds key management for SPs that rarely use it |
| D-3 | SAML IdP-initiated SSO? | **Yes, per SP opt-in**, default off. It is the flow most enterprise SaaS onboarding guides still describe; unsolicited responses are the replay risk, hence the opt-in |
| D-4 | SSF receiver (consume signals from upstream IdPs) alongside the transmitter? | **Later.** Transmitting is what relying parties ask an IAM for; receiving matters once AXIAM federates to an upstream that transmits |
| D-5 | CIBA now (W5) or after a first adopter? | **W5**, because FAPI-CIBA is the natural next certification after FAPI 2.0 and the device grant already paid for the pending-authorization machinery |
| D-6 | Front-channel logout | **Decline**, record (G-12) |
| D-7 | authentik as a benchmark target | **Yes** (G-10); the authentik comparison makes no performance claim today and says why |
| D-8 | Phase 23 in `roadmap.md` | **Yes**, on acceptance of this plan |
| D-9 | *Taken by the orchestrator, 2026-10-02, on T23.1.2's escalation F-1.* Where does a refreshed honour-lane ID token get `auth_time`/`acr`/`amr` once the browser session it came from has rotated? Today `session_evidence_for_refresh` reads the session row the code was issued under, and `AuthService::refresh` deletes that row, so after one browser-session rotation the refreshed ID token carries no evidence (OIDC Core §12.2 wants the original `auth_time`) | **Snapshot it on the OAuth2 refresh token**, exactly as the authorization code already does and as R-2 did for `requested_userinfo_claims`: optional columns on `oauth2_refresh_token` (next schema version, no backfill), written at code exchange from the code's snapshot, copied verbatim across OAuth2 refresh rotation, read by the refresh grant. A pre-migration row (columns absent) falls back to today's live-session lookup, so nothing gets worse. Emission stays gated by the honour lane, unchanged. Rejected: a rotation-lineage pointer on the session (a second source of truth for the same event, and a join on every refresh) |
| D-10 | *Taken by the orchestrator, 2026-10-02, on T23.1.2's escalation F-2.* What does AXIAM record when a federated IdP asserts an authentication instant in the future? `AuthenticationEvidence::upstream` takes it unbounded, and `honour.rs` clamps a future instant to "0 s old", so a session can stay fresh for `max_age` indefinitely and an ID token can carry a future `auth_time` | **`authenticated_at = min(upstream instant, verification instant)`**: never later than the moment AXIAM verified the assertion, so the evidence can only understate freshness (the rule the pre-v55 decode already follows). An instant later than the verification instant by more than the federation path's existing clock-skew allowance is additionally logged at `warn` with the IdP named. No new configuration |
| D-11 | **Taken by the maintainer, 2026-10-03 — option 1** ([issue #516](https://github.com/ilpanich/axiam/issues/516)): at sign-in, mint a second, path-scoped OP-session cookie for each per-tenant issuer prefix (`Path=/t/{tenant_id}/oauth2/authorize`, later also the SAML SSO path), with the same attributes (`HttpOnly; Secure; SameSite=Lax`), lifetime and session binding as `axiam_op_session`; the bare-path cookie is unchanged. Logout, `end_session` and revocation clear every cookie a session minted, which also decides F4 residual P23W1-10. Implemented by **T23.1.8** in W2, which must merge before W3. *Raised by T23.1.3, 2026-10-03.* Browser SSO on a T21.6 per-tenant issuer path: the `axiam_op_session` cookie is `Path=/oauth2/authorize`, which is not a prefix of `/t/{tenant_id}/oauth2/authorize`, so the browser never sends it there and the login hop always ends in `login_required` (fails closed). G-2's SAML SSO endpoint (`/saml/v2/{tenant}/sso`) reuses the hop and meets the same wall | **Decide before W3 (G-2).** Options: a second, path-scoped cookie per tenant prefix minted at sign-in; widening `Path` (which turns the browser's scoping into a code-enforced invariant; `__Host-` would need `Path=/` anyway); or a documented limitation that per-tenant issuers are API-only. The orchestrator leans to a per-prefix cookie, as the narrowest change, but it is an architectural choice about what an AXIAM issuer is |
| D-12 | **Accepted as recommended, 2026-10-03**; rides T23.1.4 in W2. *Raised by T23.1.1, 2026-10-02.* An **essential** `claims.id_token.auth_time` on a `fapi2` client is dropped, while OIDC Core §2 makes `auth_time` REQUIRED when requested as essential | **Refuse it on `fapi2` exactly as `id_token.acr` now is** (`invalid_request`), for the reason T23.1.1 gave: a silently dropped essential request is a downgrade. Small; a candidate for T23.1.4 in W2 |
| D-13 | **Accepted as recommended, 2026-10-03**; binding on T23.5.2. *Raised by T23.9.1, 2026-10-02.* G-5 signs SETs "with the tenant's EdDSA issuer key", which does not exist: there is one deployment key (see the note under G-5's *Design*) | **Use the deployment key at the tenant's JWKS URL for G-5**, as ID tokens do today, and keep per-tenant keys a separate decision with its own key-management cost (the verifiable-credentials design needs per-tenant ES256 keys anyway, and is where that cost should be argued) |
| D-14 | *Taken by the orchestrator, 2026-10-03, on T23.1.4's escalation.* On the honour lane, `max_age=0` can never yield a code: `honour::evaluate` re-authenticates when `elapsed >= max_age`, so on the return leg a session signed in a moment ago is still "too old" and the answer is `login_required`. Plan §4.3, test T2.1 and T-239's text pinned that literally ("always reauthenticate … never yields a code"), but OIDC Core §3.1.2.1 (1.0 incorporating errata set 2) says the OP re-authenticates when the elapsed time is *greater than* `max_age`, and adds that `max_age=0` is equivalent to `prompt=login`, after which a code is issued | **`max_age=0` is handled as `prompt=login`**: the outbound leg always re-authenticates (the `reauth=1` hop, as today), and the return leg, whose session the hop itself just created, is answered with a code and an ID token whose `auth_time` is the new authentication. Positive values keep `>=` (one instant stricter than the clause; harmless, and pinned by `oidcc-max-age-1`). The return-leg marker's accepted residual (F4 P23W1-08) applies unchanged, exactly as it does to `prompt=login`. Rejected: keeping it (an RP sending `max_age=0` could never sign in, which contradicts the errata note) and switching every value to strict `>` (changes the pinned `max_age=1` behaviour for no gain). Implemented in T23.1.4; amends test T2.1 and T-239's mitigation text |
| D-15 | *Taken by the orchestrator, 2026-10-03, before T23.3.1, so the Sonnet task does not stall on it.* §4 G-3 says `bind_secret (secret provider, R-5 pattern)`, but the secret provider is deployment-wide and addressed by static logical names (`axiam_core::secrets`), while a bind secret is per tenant and set by a tenant administrator | **Encrypted at rest in the directory configuration row, exactly as the per-tenant SMTP password is** (`crates/axiam-db/src/repository/email_config.rs`): AES-256-GCM with a fresh nonce per write, the 256-bit key fetched from the secret provider under a **new logical name `directory_encryption_key`** (R-5: the key lives in the provider, never in the database or configuration file). The key is optional: without it the directory feature is unavailable and creating a configuration fails closed with a message naming the key, as OPAQUE does without its keys. The secret is write-only through every API (never returned, `Debug`-redacted, absent from audit rows), and decrypted only at bind time. Rejected: a per-tenant provider reference (`bind_secret_ref` resolved by name), because it would make a tenant administrator's configuration depend on a deployment operator's vault layout, and the admin console (T23.3.8) could not set the secret at all |

---

## 9. What this plan does not do

- It does not reopen any item the comparisons list as closed (§2, *Closed,
  not gaps*).
- It does not propose a hosted offering, a flow designer, outposts or
  governance workflows (G-14).
- It does not change AXIAM's licence, database or broker; G-8 makes the
  broker optional, not absent.
- It does not implement verifiable credentials (G-9 is design only) or
  RADIUS (G-11 is a spike).
- It does not edit `roadmap.md`, `design-document.md` or the three comparison
  documents; each landed item does that in its own PR.

---

## 10. Kickoff prompt for a fresh session

The prompt below starts Phase 23 in a new Claude Code session. It is written
for an **orchestrator** that delegates every task to an executor subagent with
the model §6 assigns, because a Claude Code session cannot change its own model
mid-turn but can spawn a subagent on any model. Start the orchestrator on
Opus 5.5 (`claude --model claude-opus-5-5`, or `/model opus` once inside): it
reads the plan once, reviews every executor's diff, and runs the F4 review, so
it should be the stronger model even though it writes little code.

```text
Read CLAUDE.md, then claude_dev/competitor-gap-remediation-plan-2026-10-02.md in
full. It is the plan for Phase 23 (competitor gap closure). Execute it, wave by
wave, in the order §5 gives (W1 → W6), starting from the top of W1.

You are the orchestrator. You do not write feature code yourself. For every task
in the §6 tables you spawn one executor with the Agent tool, passing
`model: "opus"` when §6 says Opus 5.5 and `model: "sonnet"` when it says
Sonnet 5.5 — never the other way round, and never both. The executor prompt
must contain: the task id and the full text of its §4 item and §6 row, the
acceptance criteria, the bookkeeping the task owes from §7, the feature branch
name, and the disk-hygiene rules from CLAUDE.md (narrow cargo commands,
`cargo clean` between tasks, the swagger-ui placeholder, `protoc` and
`--no-default-features` where the server binary is built). Executors in the same
wave that touch disjoint crates may run in parallel with `isolation: "worktree"`;
executors that share a crate run sequentially.

Branching: one feature branch per wave, `claude/phase23-w<N>`, cut from the
latest `main`. Each task is one or more signed commits on that branch; the
commit message names the task id. At the end of a wave, spawn an Opus 5.5
executor for the F4 security review of the whole wave diff against
claude_dev/threat-model-stride.md, fix what it finds, then open one PR per
wave to `main` with the detailed description CLAUDE.md requires and the issues
it closes, and subscribe to its activity. Do not start the next wave's branch
from an unmerged wave unless its tasks are independent of the unmerged work
(§5 lists the dependencies); otherwise wait for the merge.

After each executor finishes, before accepting its work: read its diff, run the
repo's fast checks yourself (`cargo fmt --all --check`, the narrow
`cargo clippy -p <crate> --all-targets -- -D warnings`, the crate's tests,
`scripts/check-crate-layering.py`, `scripts/check-doc-links.sh`), confirm the
acceptance criteria in §4 are met by tests that exist and pass, and confirm the
§7 bookkeeping (CHANGELOG under [Unreleased], contract section, OpenAPI
regeneration, threat-model entries in the same commit where §7 requires it). If
anything is missing, send the executor back with the gap named; do not fix it
yourself unless it is a one-line change. If an executor on Sonnet 5.5 reports
that the task needed a design decision the plan does not pin, stop that task,
take the decision yourself, write it into the plan's §8 table as a new D-row,
and resume on the model §6 assigns.

As each task lands, add an EXECUTED block at the head of its §4 item in the plan,
in the form claude_dev/remediation-plan-2026-09-12.md uses: what shipped, which
tests went in, what the plan did not anticipate, what the model and the docs now
say. When a whole item (G-n) is complete, flip its row in the three
competitor-comparison documents and add a dated change-log line there. When W1
lands, add Phase 23 to claude_dev/roadmap.md (D-8) with T23.x entries mapping
to §6.

The §8 decisions D-1 … D-8 are accepted as recommended unless the maintainer
has written otherwise in the plan since. SAGE MCP: call sage_inception first if
it is connected; if it is not, say so once and continue.

Report at the end of every wave: tasks landed with commits, tests run, what was
left out and why, PR link, and what the next wave needs from the maintainer.
```

Three notes on running it. First, the Agent tool's `model` values are aliases
to the current generation, so `opus` and `sonnet` resolve to Opus 5.5 and
Sonnet 5.5 today and will move with the catalogue; pin the exact ids in the
prompt only if a specific generation must be reproduced. Second, the
orchestrator's own tokens are a small share of the phase (it reads and
reviews, the executors write), so running it on Opus 5.5 costs little and
buys a stronger review of every Sonnet diff. Third, the per-wave PR is the
unit of merge and of the F4 review; a task is not done until the wave's PR is
green and merged, as CLAUDE.md's development process requires.
