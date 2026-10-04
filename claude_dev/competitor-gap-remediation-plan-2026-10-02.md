# Competitor gap remediation plan — 2026-10-02

> **Status: ACCEPTED — in execution as Phase 23.** W1 (G-1 X7.1–X7.3, G-4,
> G-9, G-12, G-15) executed 2026-10-02/03 on `claude/phase23-w1` and merged
> (PR #521); D-9 and D-10 taken during it. W2 (G-1 X7.4–X7.9 and the
> submission package, T23.1.8, G-3's crate and bind path) runs on
> `claude/phase23-w2`: D-11 taken by the maintainer on 2026-10-03 (option 1,
> issue #516), D-12 and D-13 accepted as recommended, D-14 … D-18 taken during
> it; merged as PR #527. W3 (G-2 SP registry, signing key and SSO; G-3 JIT,
> mapping, sync, management, e2e) ran on `claude/phase23-w3`, with D-19 and
> D-20 taken at its start and D-21 … D-34 during it; merged as PR #534 on
> 2026-10-04. G-3 is complete; G-2 continues in W4 (G-2 SLO, metadata, SP
> registry routes, console, e2e, §29; G-5 dispatcher, SETs, streams), which runs
> on `claude/phase23-w4` with D-35 taken at its start. Written against AXIAM `1.0.0-beta17` from the three
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
> **EXECUTED (partly) — G-1, W2: T23.1.4 – T23.1.7, 2026-10-03.** On
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
> - **T23.1.5** (`34a5a8f`, `35a281e`, `6e01254`, `744651b`; Sonnet 5.5). An
>   audit of X7.7 (shipped as schema **v57**, not v51) and X7.8 against RFC
>   6749 §2.3.1, RFC 7617 and OIDC Core §5: every requirement tabulated, about
>   thirty new pinning tests (the §2.3.1 decode edge cases end to end, two
>   `Authorization` headers, the redaction at PAR, revocation and
>   introspection, the strong-client refusal at the three ordinary grants,
>   cross-tenant consent, no sensitive claim in the access token, introspection
>   or a refreshed ID token, the OIDC Core §5.1.1 address shape, SCIM as the
>   writer over HTTP). Two defects, each with a test that failed first: (1)
>   **with per-client rate-limit keying configured, a `client_secret_basic`
>   client had no per-client bucket**, because the limiter read `client_id`
>   from the form only, so its secret could be guessed from many addresses
>   (the default `ip` keying was never affected); the key now falls back to the
>   id the Basic header decodes to, through the same parser the handlers use.
>   (2) The `fapi2` client-authentication rule did not run at PAR,
>   introspection or revocation, decided as **D-17**. Both amend T-253.
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
>
> **EXECUTED — T23.1.8 (D-11), 2026-10-03** (`f7f4c4c`, `4ee5e64`, `4a1e961`,
> `c74fe80`; Opus 5.5). Browser SSO now works on a T21.6 per-tenant issuer
> path. Every completed sign-in (password, OPAQUE, MFA verify, forced
> enrolment, both WebAuthn ceremonies, the federation handoff) mints
> `axiam_op_session` at every path `op_session_cookie_paths` names: the bare
> `/oauth2/authorize` and, when `tenant_issuer_paths` is on,
> `/t/{tenant_id}/oauth2/authorize` for the session's own tenant only. Same
> name, same value, same attributes and lifetime; the paths never prefix one
> another, so no request carries two copies and the existing tenant-keyed
> digest lookup serves both paths without a new resolver. Removals are built
> from the same list, and the per-path setter is private, so nothing mints at
> a path the list does not name. Logout and both `end_session`s clear every
> copy, and P23W1-10 is closed by the `/logout` hop decided as **D-16**.
> Threat model **2.19.0**, **T-290**, T-237 and T-238 amended; OpenAPI gains
> `/oauth2/authorize/logout`; no contract or schema change.
>
> Tests: `oauth2_tenant_path_sso_test.rs` (25) re-runs the T23.1.3 audit list
> on the tenant path (code from the tenant cookie alone, the hop end to end,
> fixation, cross-user, factor still owed, `POST` unrouted, nothing reflected,
> the decline arm, M7, `account_may_act` with `PendingVerification` still
> served, the hostile `return_to` list, `prompt=none`), cross-tenant refusal in
> both directions including a digest that matches a live row in the other
> tenant, both cookies cleared on every logout, and P23W1-10; six `csrf.rs`
> unit tests pin the path list, its disjointness and the mirrored removals;
> each sign-in path's own suite asserts both cookies.
>
> What the plan did not anticipate. Three defects the cookie had been hiding,
> each fixed: the tenant-path `return_to` echoed the `tenant_id` that
> `TenantPathScope` appends, so **every return leg on a tenant path was
> refused** `invalid_request` (test failed first); the stale-cookie removal on
> a tenant path used the bare path and never matched; and **`POST
> /api/v1/auth/logout` revoked nothing after an admin switched tenant**,
> because it looked the session up in the acted-on tenant rather than the
> principal's (test failed first). `end_session` without a hint now costs the
> RP one extra `302` on the bare path too. The threat-model text landed in
> the third commit rather than with the first two code commits, all in this
> wave. For W3: the SAML SSO path is one more entry in
> `op_session_cookie_paths` (not gated on `tenant_issuer_paths`), plus a SAML
> arm for the `return_to` validator, the SPA's `isAuthorizePath` and the
> stale-cookie removal, with the 56-candidate list re-run against it.

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

> **EXECUTED (partly) — G-2, W3: T23.2.1, 2026-10-03** (`8d0d875`, `5f4129c`,
> `9932129`, `e1397b6`, `bfb2961`; Sonnet 5.5 for the registry and the
> credential store, Opus 5.5 in the hand-over session for `9932129`). The
> data layer of the SAML IdP; nothing serves SAML yet. **D-20** shipped as the
> layered, disable-only setting `saml_idp_enabled` (organization default,
> tenant may only turn it off, default `false`). `SamlServiceProvider` lives
> in `axiam-core` with its write-time validator in `axiam-federation`
> (`saml_sp::validate_saml_service_provider`): the ACS list is refused exactly
> where an OAuth2 redirect URI would be, plus a `*`; certificates are one
> `CERTIFICATE` block and a private key is refused by name; there is **no
> `sign_assertions` field**, so assertions cannot be configured unsigned; D-2
> (encryption off) and D-3 (IdP-initiated per SP, off) are the defaults. The
> redirect rule now exists once and the admin OAuth2 client API calls it.
> **D-21** shipped: `CertificateType::SamlSigning` (keyUsage
> `digitalSignature`, EKU `id-kp-documentSigning` only, no SAN, RSA-4096) is
> `serde`-skipped, so the OpenAPI enum is byte-identical, and it is refused by
> certificate generation, CSR signing, the bind endpoint, device login and
> mTLS. The IdP credential is a `saml_idp_credential` row (one `active` and
> one `next` per tenant, enforced by a computed `slot` under a UNIQUE index),
> never a `certificate` row; its key is sealed through the database custodian
> explicitly, only `get_active_sealed` selects it, `retire` destroys it in the
> same write, and both tables go with their tenant in the tenant-delete
> transaction. Schema **v72** (registry, setting, credential). Tests: 12 + 12
> repository tests, 6 PKI tests (profile parsed back from the DER, chain, the
> sealed bytes hold no PEM and decrypt to the certificate's key, refusals of
> another organization's, an imported, an expired and a revoked CA, the
> 730-day cap), the refusal tests in `cert_test`, `mtls_test` and
> `device_auth_test`, 28 validator unit tests, the v72 schema tests.
>
> What the plan did not anticipate. The model has no "signing CA" flag; a CA
> AXIAM cannot sign with is one whose custody is `External`, refused by the
> custodian. The issuing scope is a caller parameter: a tenant principal gets
> only its tenant's CA; T23.2.5 passes it from the principal. A retired
> credential's key is destroyed, so rotation must publish `next` before
> promoting, and there is no promote verb yet (T23.2.5). The service returns an
> expired active credential; the signer (T23.2.2) decides. RSA-4096 key
> generation makes the PKI tests ~3 minutes in a debug build. No threat entry:
> the signing-key-at-rest threat is T23.2.2's (§7 rule 2, pulled forward to the
> Opus task that first signs with it).
>
> **EXECUTED (partly) — G-2, W3: T23.2.2, 2026-10-03** (`0d0aaaa`, `c3db35c`;
> Opus 5.5). `axiam_federation::saml_idp` (behind `saml`), a library with no
> route: `idp_entity_id`/`idp_sso_url`/`idp_slo_url` as one function of the
> root issuer and the path tenant; `SamlIdpIssuer::issue` builds the
> assertion (bearer confirmation and `Conditions` five minutes, audience = SP
> entity id, `Recipient`/`Destination` = the ACS used, `InResponseTo` only when
> SP-initiated, `SessionIndex` = the AXIAM session id, `AuthnInstant` =
> `authenticated_at`, a pinned `amr` → `AuthnContextClassRef` table, attributes
> XML-escaped over every `AttributeSource`), signs it always and the `Response`
> after it by policy (`rsa-sha256`, `sha256`, exclusive c14n, the certificate
> in `KeyInfo`), and re-verifies its own output before returning it; failure
> responses are status-only and **never signed**, so the key mints no
> wrapping gadget. A credential outside its validity window refuses to sign.
> The pre-hop checks T23.2.3 needs are exposed on their own (`check_acs_url`,
> `check_request_id`, `check_relay_state`, `check_allowed_groups`). **D-22**:
> the persistent `NameID` is HMAC-SHA256 under a new optional deployment key
> `saml_pairwise_key`, keyed on the SP entity id, independent of the signing
> credential; without the key a persistent sign-on is a `Responder` failure.
> D-2's encryption is **refused** for now (`samael` has no encryption API): an
> `encrypt_assertions` SP gets `Responder`, never plaintext. Threat model
> **2.21.0**: trust boundary AXIAM ↔ SAML service providers, **T-304 … T-316**
> (316 threats, 298 mitigated, 18 open; T-306, T-309, T-312, T-313 open).
> Tests: 41 in `saml_idp::tests`, including a round trip through AXIAM's own
> SP verifier, xmlsec against the credential certificate only, a changed byte
> in every signed element, XSW1–XSW4 copies refused, pairwise stability across
> a rotation and separation across SPs, tenants and users.
>
> What the plan did not anticipate. **A Critical, pre-existing defect in the
> SP verifier** (`saml.rs`): only the first `ds:Signature` was verified and any
> reference naming the assertion bound it, so a document the upstream IdP had
> signed for another purpose vouched for a forged assertion. Fixed in the same
> task per **D-23** (`c3db35c`): a signature is admitted only as the enveloped
> child of the `Response` root or of its `Assertion`, each is verified on its
> own node with xmlsec, the consumed assertion must carry its own verified
> signature; 27 gadget placements and the extra-unsigned-signature variants
> are refused; T-67 amended, CHANGELOG *Security*. No other SP-side SAML
> signature check exists (there is no SP-side SLO, and IdP metadata
> signatures are not checked at all, an absent control rather than a
> sibling). Also: `SessionIndex` = session id lets colluding SPs correlate
> (T-312); most accounts never have `email_verified_at`, so an email `NameID`
> for an unverified address stays open as T-313 for T23.2.3 to decide;
> `samael` signs only the first template, so the assertion is signed alone and
> embedded; the `pem` crate keeps copies of the key text, so it is decoded by
> hand into `Zeroizing` buffers.

> **EXECUTED (partly) — G-2, W3: T23.2.3, 2026-10-03** (`7f1d324`, `9b49d18`,
> `d6e9961`, `e7f7845`; Opus 5.5). The SSO endpoint, `/saml/v2/{tenant}/sso`,
> on both bindings, with IdP-initiated sign-on (`/sso/idp-initiated`, D-3) and a
> second leg (`/sso/continue`). **D-24**: the first leg refuses everything
> decidable without a principal — with an error page that posts nowhere, or, once
> the ACS is a registered POST endpoint, a posted unsigned failure — and holds the
> checked request in `saml_authn_request` (schema **v73**) under an opaque handle
> bound to the browser by a per-handle `SameSite=Lax` cookie; the second leg
> resolves the OP cookie (now minted at `/saml/v2/{t}/sso` too, pinned in the same
> commit) through the tenant-keyed lookup, applies `account_may_act`, runs the
> login hop with the SAML arm of `return_to` (server and SPA, the T23.1.3 list
> re-run against it), binds `ForceAuthn` to the request's outbound instant (a
> forged marker yields `AuthnFailed`), never hops under `IsPassive`, and consumes
> the handle on the X6 arbiter before issuing. Request IDs are single-use per SP
> for longer than the `IssueInstant` window. Receiving
> (`saml_idp::request`): DTDs refused on the bytes, NUL and non-UTF-8 declarations
> refused, a 64 KiB inflate cap, the Redirect signature over the exact query
> octets (`samael`'s `UrlVerifier` re-encodes), the POST signature under D-23's
> placement rule. **D-25** closes T-313: an email is asserted only when verified or
> the account is `Active`. **D-26**: the IdP-initiated trigger and what a refusal
> looks like. **D-27**: a handler may set a stricter CSP (the auto-post page:
> nonce, `form-action` = the ACS origin), the `end_session_per_min` preset with
> buckets of its own, the D-20 `404` before the body is read and on every method.
> Composition: the pairwise key is read in `axiam-server`, documented in the
> deployment guide and the website configuration page; the pending rows are swept.
> Threat model **2.22.0**: **T-317 … T-330** (13 mitigated; T-325, the query string
> in request logs, Low, open), T-313 closed — 330 threats, 312 / 18. No OpenAPI
> or contract change: browser routes, compiled out of the spec build.
> Tests: 18 over HTTP (`saml_idp_sso_test.rs`), 17 receiving unit tests, 7 + 1
> repository/schema tests (100 rounds of 8 concurrent consumes on surrealkv), the
> D-25 unit test, the cookie-list pins and the suites that count the copies.
>
> What the plan did not anticipate. The global security-headers middleware
> overwrote every response's CSP, so the auto-post page could not run its one
> script or post cross-origin without D-27. The `/oauth2/authorize` preset the
> task names does not exist (that route has no limiter). The OP cookie cannot
> reach a cross-site POST at all, which is what forces two legs for every
> binding. `tracing-actix-web` records every route's query string, `RelayState`
> and the handle included (T-325, for the F4 review). Chrome applies
> `form-action` to post-submission redirects, so an SP whose ACS redirects
> cross-origin before rendering will need its ACS on that origin. An HTTP-level
> race test on `kv-mem` would be flaky by design (`tests/common`), so the
> single-use race is pinned at the repository on surrealkv and sequentially over
> HTTP. Left for T23.2.4: `SessionIndex` per SP (T-312) and SLO signing (T-316's
> constraint). For T23.2.5: the metadata's `SingleSignOnService` locations are
> `idp_sso_url` for both bindings; the SP write path should refuse
> `encrypt_assertions` and validate that a signing SP's certificate parses (the
> endpoint answers `sp_certificate` otherwise). For T23.2.7: `test_support` in
> `saml_idp` (doc-hidden) signs requests the way an SP library does.
>
> **EXECUTED (partly) — G-2, W4: T23.2.8, 2026-10-04** (`e79b4cb`, `afa9637`,
> `f1a832f`, `5ef1aad`, `cd96669`; Opus 5.5; documentation and decisions only,
> run in a worktree in parallel with T23.5.1). **D-37 … D-42** settle what W4's
> Sonnet tasks needed: a per-SP `SessionIndex` in a `saml_sp_session` row (D-37,
> closes T-312 when T23.2.4 lands, and the record SLO needs anyway, since the
> pairwise `NameID` cannot be reversed); the SLO protocol on both bindings, every
> SP message signed by its registered certificate and verified per node or over
> the exact query octets, AXIAM signing its own logout messages only for verified
> or holder-initiated logouts and with a detached signature on Redirect (D-38);
> whole-session revocation first, then sequential front-channel propagation in a
> `saml_logout_run`, the OP cookie cleared blind and an IdP-initiated trigger at
> `/sso/logout` (D-39); unsigned IdP metadata with active then next credentials
> and the D-20 `404` when nothing is publishable (D-40); SP metadata import as a
> parse to a draft, never a write, URL fetches only through `guarded_fetch`, and
> nothing trusted from an unsigned document (D-41); the §29 routes compiled in
> every build, with the write-time refusals the validator lacked (D-42).
> **Contract 1.55, §29 SAML service provider registration** (11 operations,
> namespace `saml`, permissions `saml_sp:read`, `saml_sp:write`,
> `saml_idp:credential`, a `saml_admin` bucket). Threat model **2.25.0**:
> **T-357 … T-384** entered *Open* because their controls are specified but not
> yet built (T23.2.5 and T23.2.4 flip them); T-380 (a revocation outside SAML
> reaches no SP) is an accepted Open; T-309 and T-312 amended. Design document
> **§8e**.
>
> What the plan did not anticipate. The committed OpenAPI is exported without
> `saml`, so gated registry routes would reach no SDK (hence D-42). `/slo` can
> never see the OP cookie (its path is scoped to `/sso`, and a cross-site POST
> carries no `Lax` cookie). `entity_id` must be immutable, because the pairwise
> identifier is keyed on it. The IdP URL functions sit in the gated module and
> move. Until W4's later tasks land, the site shows 44 open threats.
>
> **EXECUTED (partly) — G-2, W4: T23.2.5, 2026-10-04** (`afe16fa`, `6fe95d0`,
> `241bcc4`; Sonnet 5.5). The §29 surface (`handlers/saml_admin.rs`), compiled in
> every build (D-42): SP CRUD with the validator and the four D-42 refusals
> (`encrypt_assertions`, an SP certificate that does not parse or is weaker than
> RSA-2048 / ECDSA P-256, a changed `entity_id`, a group outside the tenant),
> `parse_sp_metadata` as a parse to a draft (D-41: `guarded_fetch` only, 512 KiB,
> markup declarations and other encodings refused on the bytes, aggregates
> refused, nothing trusted from an unsigned document), and the credential routes
> with **promote** in one transaction, retried on write conflict so the race's
> loser gets `409` (closes T-309's rotation window). The IdP metadata endpoint
> (D-40) publishes active then next, unsigned, with `ETag`/`304`, the D-20 `404`
> (no publishable credential included) and its own bucket; the IdP URL functions
> moved to the ungated `axiam_federation::saml_idp_urls`. Permissions
> `saml_sp:read`, `saml_sp:write`, `saml_idp:credential` (human-only), bucket
> `saml_admin` (30/min). OpenAPI and the registry: 179 operations, 26
> namespaces. Threats **T-357 … T-365, T-367 … T-369 Mitigated, T-309 closed**,
> each citing its tests. Tests: 38 HTTP tests (28 without `saml`), including an
> 8-round promote race over HTTP on surrealkv; 22 federation tests; repository
> tests incl. a 25-round promote race.
>
> What the plan did not anticipate. §29 said a service-account token is `403`;
> every human-only family answers `401`, so §29 is amended (**D-43**). A revoked
> or expired issuing CA surfaced as a `500`; the credential service maps exactly
> those to `400`. `samael` types `SPSSODescriptor/@cacheDuration` as an integer
> and requires an ACS `index`, so some real SP metadata is refused as not SP
> metadata (a residual for T23.2.7's Keycloak round trip). T23.5.1's rustdoc
> named a future env var the config-key check took for a real one (fixed). The
> SP-delete cascade has a named hook (`SP_DELETE_CASCADE`) for T23.2.4's
> `saml_sp_session` rows.

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

> **EXECUTED (partly) — G-3, W2: T23.3.1, 2026-10-03** (`7279f66`, `2f60f4f`,
> `227af53`; Sonnet 5.5; issue #522). The crate `axiam-directory` exists at
> layer 3, in the layering table and `crate-layering.md` from its first
> commit, opted into `missing_docs` (CLAUDE.md's list now names it), with no
> feature flag and no network code yet. `DirectoryConfig` lives in
> `axiam-core` as the pinned fields plus `enabled`, `kind` (`OpenLdap` |
> `ActiveDirectory`, which only chooses defaults: `entryUUID`/`objectGUID`,
> reverse `member`/`memberOf`, `modifyTimestamp`/`uSNChanged`, `uid`/
> `sAMAccountName`) and `group_nesting_depth` (0–10, default 5); the
> repository is schema **v70**, one row per tenant. The bind secret follows
> **D-15**: AES-256-GCM in the row through the existing
> `axiam_auth::crypto` helpers, keyed by the optional provider key
> `directory_encryption_key`; no read returns it, only
> `decrypt_bind_secret` does; without the key a save is refused naming the
> key, serving is `503`, and boot is unaffected. `axiam_directory::config::
> validate` is pure and refuses at config time a plaintext URL (`ldap://`
> without StartTLS, `ldaps://` with it, any other scheme), userinfo, a path
> or query, a filter template without exactly one `{username}` in value
> position, an empty bind secret (an RFC 4513 unauthenticated bind), and a
> trust anchor that is not a parseable CA certificate; an empty anchor list
> means the platform roots the rest of the workspace uses. Tests: 44 unit
> tests in the crate, 20 repository tests, the v70 schema tests, the key's
> name and environment variable pinned.
>
> What the plan did not anticipate. The brief said the directory row should
> go "with the tenant, exactly as its email config is": **no tenant-delete
> cascade exists for anything**, the email configuration included, so a
> deleted tenant leaves its SMTP ciphertext behind. The directory row is now
> deleted in the same transaction as its tenant (tested); the email
> configuration's missing cascade is carried to the F4 review. No threat
> entry yet: the connector's elements, the bind secret at rest among them,
> are written by T23.3.2 with the network path, pulled forward from T23.3.7
> so that §7 rule 2 holds.
>
> **EXECUTED (partly) — G-3, W2: T23.3.2, 2026-10-03** (`1c17c68`, `42d0441`,
> `f17c7e1`, `352351d`, `176219e`, `0552b19`; Opus 5.5). The security core
> of G-3. `ldap3 0.12` over `rustls 0.23` (`tls-rustls-ring`): neither
> OpenSSL nor `native-tls` is in `Cargo.lock`. TLS is mandatory, TLS 1.2
> floor (AD and many OpenLDAP builds stop there), the trust store is the
> tenant's anchors alone or the public roots when there are none, never
> both, the name checked is the URL host, and StartTLS is completed before
> anything is bound or it fails closed. One function escapes per RFC 4515
> and is the only way a login name enters a filter; no DN is ever built.
> Referrals and search references are neither followed nor matched. The
> pool is bounded per tenant and in total, with connect, operation and
> whole-flow deadlines; the user bind always runs on a fresh connection that
> is never pooled; an empty password is refused with zero packets sent. The
> port `DirectoryAuthenticator` lives in `axiam-core`, is implemented in
> `axiam-directory` and is attached to `AuthService` by `axiam-server` only,
> so the layering holds. The marker is **D-18**. A directory account signs
> in only through the directory, behind the existing lockout (a locked
> account never reaches the directory, so AXIAM cannot be used to lock
> accounts in AD), with no fallback to a local hash, the answering entry
> bound to the account's marker, timing equalised with the dummy Argon2
> verify, and `amr = [pwd]`. Every local password door refuses a directory
> account: change, reset request (answered as an unknown address) and
> confirm, OPAQUE login and enrolment, the SCIM password write and gRPC
> `ValidateCredentials`. The connector's threat entries were pulled forward
> from T23.3.7: threat model **2.20.0**, a trust boundary AXIAM ↔ tenant
> directory, **T-291 … T-303**, of which **T-300 is open** (a
> tenant-chosen directory host is not held to `guarded_fetch`'s
> private-address policy; reachable once T23.3.8 adds the management
> routes). Tests: an in-process TLS test directory on `ldap3_proto` (25
> client tests: ldaps and StartTLS, anchors, name mismatch, refused
> StartTLS, referrals, zero and two matches, the injection attempt asserted
> on the filter the server parsed, AD `data 533`, pool bounds, timeouts),
> 64 unit tests, 7 authenticator tests, 12 `AuthService` tests, the marker's
> 7 repository tests, and REST, SCIM and gRPC refusal tests.
>
> What the plan did not anticipate, and what W3 must pick up.
> `SearchEntry::construct` panics on malformed BER, so entries are parsed by
> a fallible parser of AXIAM's own; `ldap3`'s codec has no per-message size
> cap (residual in T-295). `validate` accepts IPv6-literal URLs that `ldap3`
> cannot name-check, so they always fail closed: **T23.3.8 refuses them at
> config time**. A tenant in `opaque_mode = required` refuses `/auth/login`
> before the credential is read, so directory accounts cannot sign in there:
> **T23.3.8 refuses a directory together with `required`, both ways**, and
> should add an operator allow-list of directory hosts for T-300. The JIT
> seam is `AuthService::login_unknown_user`. Passkeys a directory account
> enrolled keep working until the account is disabled, so the sync job
> (T23.3.5) must disable or soft-delete vanished and disabled entries
> (T-303). Its threats and contract §30 start at T-304.
>
> **EXECUTED (partly) — G-3, W3: T23.3.3, 2026-10-03** (`7bd2b2a`,
> `b70fa3e`, `f5db88e`, `110a25e`; Sonnet 5.5). Just-in-time provisioning at
> the seam T23.3.2 left, `AuthService::login_unknown_user`. The port gained
> `authenticate_for_provisioning`, gated inside the authenticator, so a tenant
> without an enabled directory and `jit_provisioning` answers before the bind
> secret is decrypted or a socket opens, and `lookup_entry` (the same escaped
> exactly-one search, no user bind) for linking. The hash permit is taken
> first and the dummy verify runs beside the directory call, so every
> non-success branch is the unknown-user answer at its cost, and saturation is
> the same `503` before the directory hears anything. On success a cleaned
> profile (username and email refused, not repaired, when they hold control,
> whitespace or bidi characters or are overlong; display name stripped and
> capped, stored where `ProfileClaims` reads it) passes a case-folded
> collision probe over both columns of every account, tombstones included, and
> is created by one `CREATE`, `Active` and marked (**D-29**), the v71 unique
> indexes deciding a race. **D-28**: JIT never links; a collision is the
> generic failure plus a `directory.jit_refused` audit row.
> `link_local_account_to_directory` resolves the entry by the account's
> username, refuses an entry linked elsewhere, marks the account, deletes its
> passkeys, revokes its `User` certificates (by convention, D-29), and revokes
> its sessions and refresh tokens last, through the repositories so the
> validation cache and revocation feed see it; TOTP is kept; an interrupted
> link is retried to completion. Audit rows carry identifiers and counts only,
> through a new `DirectoryAuditSink` port attached by `axiam-server`. Tests: 9
> repository, 16 `AuthService` (every refusal branch timed against the
> unknown-user cost, five collision variants, a race run six times, the full
> linking revocation set), 6 more authenticator tests against the in-process
> TLS directory, 6 cleaner unit tests.
>
> What the plan did not anticipate. No certificate is bound to a user, D-18's
> single writer, and AD entries without `mail` (all three in D-29). The
> repository does not fold case, so the probe folds explicitly and scans one
> tenant per first-ever login. "One unit of work" is ordered rather than one
> transaction, because a raw cross-table write would bypass the session
> validation cache. A case variant of an existing directory account's name
> (`ALICE` for `alice`) is refused as a collision, as a local account's would
> be. No real-server test here (layering keeps `axiam-auth` from depending on
> `axiam-directory`); T23.3.6 is the oracle. Threats listed for T23.3.7: the
> unknown-name bind oracle (T-302 widened), JIT as an account-creation oracle,
> directory-side takeover by name, attribute injection, linking completeness.
>
> **EXECUTED (partly) — G-3, W3: T23.3.4, 2026-10-03** (`624376d`,
> `ab9e41a`, `198aa66`, `5aaa7fa`, `45ee025`; Sonnet 5.5). Group mapping per
> **D-30**: `DirectoryConfig.group_mappings` (≤ 500, every group of the same
> tenant, refused at write before anything is written) and `member_of.source`
> (absent reads as manual), schema **v74**. `axiam_directory::dn::normalize`
> folds what RFC 4514 lets two spellings of one DN differ by and refuses what
> it cannot parse. Resolution on the pooled service connection: AD reads
> `memberOf` by base-object read, OpenLDAP runs the reverse search with the DN
> entering the filter only through `escape::reverse_member_filter`; depth N
> follows N levels, cycles terminate on the normalised DN, the 1 001st group
> refuses rather than truncates, a ranged `memberOf` counts as the cap,
> referrals fail. Application removes before it adds (a stop part-way leaves
> less access), never touches or duplicates a manual edge, skips a mapping
> whose group was deleted, and runs on every successful directory sign-in
> before any session or MFA challenge; a mapping that cannot be applied
> refuses the sign-in (generic answer, not counted against the account) and
> changes nothing. Membership changes flush the authorization decision cache
> for the user (local and broadcast). Tests: 13 repository, 2 schema, 39 unit
> (DN, groups, escape, mapper, config), 23 lookup tests against the
> in-process TLS directory (the injection attempt asserted on the filter the
> server parsed), 14 end-to-end over the real `AuthService`, repositories and
> authorization engine, including a role through a mapped group that is
> effective and then gone after the directory removes the user.
>
> What the plan did not anticipate. Mapping writes bypassed the decision
> cache, so a cached allow survived a removal until its TTL; a hook now
> invalidates the subject (a failed broadcast is logged and bounded by the
> TTL on other replicas). A JIT account is created before the mapping runs, so
> a failed lookup leaves an `Active` account with no memberships (it grants
> nothing). An administrator's `add_member` on a pair the directory owns does
> not promote the edge to manual, so the membership leaves with the directory
> (the safe direction). AD's primary group (`primaryGroupID`) is not resolved.
> A stale schema tripwire (`Some(&72)` with v73 registered) is corrected.
>
> **EXECUTED (partly) — G-3, W3: T23.3.5, 2026-10-03** (`02680a7`,
> `9f2e87f`, `29a8529`, `eb6bd89`, `fe97d9a`, `b6ef483`; Sonnet 5.5). The sync
> job per **D-31**, last in each cleanup tick, recorded in job health as
> `directory_sync`. A full run (first, then every 24 h, and after any skipped
> account, bound hit or untrusted watermark) reads every answer before it
> writes anything, so an error part-way changes nothing; it looks up each
> marked account by `entryUUID` or the little-endian `objectGUID` octets,
> escaped through the escape module's new binary escaper. An incremental run
> searches `(<attr> >= <watermark>)`, acts only on entries owned by a marked
> account, never concludes "vanished", and on AD takes `highestCommittedUSN`
> from the rootDSE and falls back to full on a `dsServiceName` change.
> Deactivation revokes sessions and refresh tokens, then removes the
> directory's memberships (with the decision-cache flush), then flips the
> status to `Inactive` by compare-and-set from a live status only; nothing
> re-enables, creates, links, writes `Deleted` or removes a row. The safety
> valve (> 10 % and ≥ 5) applies nothing and fails the job. Attribute changes
> follow the entry through T23.3.3's cleaners, now in
> `axiam-core::models::directory_profile`; a colliding change is skipped and
> audited. State is the per-tenant `directory_sync_state` row, schema **v75**,
> deleted with its tenant. Tests: 40 sync and 26 lookup tests against the
> in-process TLS directory and real repositories (every D-31 clause), 16
> repository, 20 unit, 4 sweep tests in `axiam-server`. The operator
> *Sync* section is in `docs/deployment/README.md`.
>
> What the plan did not anticipate. D-31 first read any
> `pwdAccountLockedTime` as disabled, which turned a temporary failed-bind
> lockout into a permanent deactivation; amended to ppolicy's permanent-lock
> value only (`b6ef483`, tests for both runs). No sweep in the tree has a
> multi-replica guard, so every replica runs the job (writes are idempotent or
> compare-and-set; reads and refresh audit rows are duplicated). Reappeared or
> re-enabled accounts are reported once (deduplicated in the state row); the
> first full run reports every already-`Inactive` account whose entry is
> present, including administrator suspensions. The valve has no override yet
> (a candidate for T23.3.8). Incremental disables have no valve, by D-31.
> Observed and carried to F4: in JIT's lost-race branch the group mapping runs
> before the status check, so it can re-add directory memberships to an
> `Inactive` account (they grant nothing while it is `Inactive`).
>
> **EXECUTED (partly) — G-3, W3: T23.3.7, 2026-10-03/04** (`7fdd540`,
> `b26d2f5`, `a2d5e4f`; Opus 5.5). **T-300 closed** per D-19 and **D-32**. The
> IP classifier moved to `axiam_core::ip_class` (one classifier for every
> outbound guard; `axiam_pki::ssrf` re-exports it). `axiam_directory::address::
> guard` resolves the host once and refuses it unless every address passes:
> loopback, unspecified, link-local (incl. `169.254.169.254`), multicast,
> special-purpose and their IPv4-mapped forms always; this host's addresses on
> the REST or gRPC port; private ranges unless the operator's
> `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS` lists them; IPv6-literal URLs.
> It runs at write time (`guard_url`, for T23.3.8) and at every connection
> (pool, user bind, group lookup, sync), and the socket is connected to the
> vetted address while TLS checks the hostname, so rebinding cannot reach
> loopback. **Frame cap (P23W2-10):** `ldap3` does its own TLS, so a counter
> beneath it would see ciphertext; AXIAM now performs StartTLS and TLS itself
> and hands `ldap3` one end of a Unix socket pair, relaying each directory
> message only after checking its declared length against
> `AXIAM__DIRECTORY__MAX_MESSAGE_BYTES` (2 MiB default) before allocating,
> definite lengths, element containment, nesting ≤ 16, and the envelope shape.
> Threat model **2.23.0**: the *Directory sync job* element, two stores,
> **T-331 … T-355** (355 threats, 337 mitigated, 18 open; **T-332 open**: with
> JIT on, an unknown name reaches the directory and no AXIAM per-name counter
> stops it); T-295 and T-302 amended. **Contract 1.54, §30 Directory
> configuration**: `get`, `set` (PUT), `update` (PATCH), `delete`,
> `link_account`, `get_sync_status` under `/api/v1/tenants/{tenant_id}/
> directory`, `bind_secret` write-only and `Sensitive<T>`, `validate` and the
> guard on every write, the P23W2-01 rule as `400`, the `opaque_mode =
> required` exclusion as `409` both ways, `503` without the encryption key, a
> `directory_admin` rate-limit bucket, audit rows that record
> `connection_moved` and never the secret; §29 stays reserved for G-2. Tests:
> 13 connector-guard tests (each refused class at guard and at connect,
> rebinding, the pinned address, the hostname TLS check over it, an over-long
> length, 20 000 nesting levels, an envelope `ldap3` would panic on), 19 unit
> tests, 5 classifier tests; every earlier directory suite green.
>
> What the plan did not anticipate. `lber` recurses without a depth bound, so
> a few tens of KB of nesting overflowed the stack and aborted the whole
> process, and `ldap3`'s decoder `expect`s on short envelopes (**T-331**,
> High, closed by the relay). The relay needs Unix sockets (AXIAM ships Linux
> only; elsewhere the connector refuses). The `url` crate does not parse IPv4
> hosts for `ldap`/`ldaps`, so the guard parses them. Own listeners are
> recognised by port on a local address only, so another replica's pod IP or a
> Service looping back is a stated residual of the allow-list. Deleting or
> disabling a directory leaves its accounts' sessions and passkeys working and
> stops deprovisioning; §30 documents it, and it is carried to F4.
>
> **EXECUTED (partly) — G-3, W3: T23.3.8, 2026-10-04** (`bda6b14`,
> `1b69d2d`, `a8e6814`, `7214346`, `7396cfd`, `ee34f10`, `7cf3b4f`, `6397ca7`;
> Sonnet 5.5). The §30 surface: `GET`/`PUT`/`PATCH`/`DELETE
> /api/v1/tenants/{tenant_id}/directory`, `POST …/links` (D-28's linking) and
> `GET …/sync-status`, behind `directory:read`, `directory:write` and
> `directory:link`, human principals only, the four writes on a new
> `directory_admin` rate-limit bucket (30/min). Every write runs, in order: the
> `503` without `directory_encryption_key` when it carries a secret,
> `config::validate`, the address guard on the URL as written (only when the
> resulting configuration is enabled, **D-33**), the P23W2-01 rule as a `400`,
> and the `opaque_mode = required` exclusion as a `409` — enforced both ways,
> the settings writes (`set_effective`, `set_tenant_override`, `set_org` for
> inheriting tenants) refusing `required` for a tenant with an enabled
> directory. `bind_secret` is a `SecretString` on two request types and on no
> response; the directory routes' own JSON error handler never echoes it;
> audit rows carry changed field names, `connection_moved`, `secret_replaced`
> and the live directory-account count. The console *Directory* page (secret
> never pre-filled, asked again when the connection moves, group-mapping
> picker over the tenant's groups, sync status, linking behind a confirmation),
> the website *LDAP / Active Directory* page, the operator guide's *Managing a
> tenant's directory* (with D-29's no-email note) and design-document **§8d**.
> OpenAPI and the management registry regenerated (168 operations, 25
> namespaces); §27.1 and §27.5 rows filled in. Tests: 27 HTTP tests (every
> §30 answer, the guard and validate refusals, P23W2-01 on each connection
> field and both verbs, both directions of the opaque-mode exclusion, the
> secret absent from responses, logs and audit rows, D-33), 72 frontend tests;
> `m2m_management_test` walks the new routes.
>
> What the plan did not anticipate. The repository's `update` demanded the
> encryption key even without a secret, so a keyless deployment could not
> switch a directory off; it now needs the key only to seal. The registry
> script classified only `PUT`; `PATCH` is now `sparse`. §30's registry
> `service_account` flag does not exist; machine refusal is the
> `HUMAN_ONLY_FAMILIES` gate. The guard's two refusals ("private address
> outside the allow-list" and "does not resolve") let a tenant administrator
> probe internal names, bounded by the bucket — carried to F4 against T-300's
> residual. The SAML IdP's handler had no frontend-coverage row; added
> ("headless for now", T23.2.6 replaces it).
>
> **EXECUTED — G-3, W3: T23.3.6, 2026-10-04** (`94733bd`, `73d82f4`,
> `f5bfc4f`; Sonnet 5.5). The oracle for T23.3.2: `docker/docker-compose.
> directory.yml` runs a real OpenLDAP (slapd 2.4.57) and a real Samba AD DC
> (Samba 4.23), pinned by digest, on their own bridge network, with the CA,
> certificates and every password minted at run time by
> `scripts/gen-directory-e2e-secrets.sh` into a gitignored directory.
> `crates/axiam-server/tests/directory_e2e.rs` (gated by
> `AXIAM_E2E_DIRECTORY=1`; a missing stack is a failure once asked for) drives
> the real §30 routes, `/api/v1/auth/login`, the authorization engine and
> `sweep_directories`: 18 tests, each scenario on both servers — JIT login,
> role through a mapped group (an unmapped `admins` grants nothing), nested
> group and depth 0, the disabled account answered as an unknown user, seven
> filter-injection payloads presented with the password of the entry each
> would select if unescaped (and the unescaped filter shown to match), the
> metacharacter entry by exact name only, the config-time refusals (plaintext,
> loopback, private outside the allow-list, metadata), an untrusted
> certificate, StartTLS, and sync deactivating a vanished and a disabled
> entry's account to `Inactive` with its sessions revoked. Ran green in the
> W3 container, and again for the orchestrator. CI:
> `.github/workflows/directory-e2e.yml` on directory paths and on dispatch. The
> real servers exposed **no defect** in the G-3 code; a real AD's
> configuration-partition search reference is ignored as T23.3.2 designed.
>
> **G-3 is complete for Phase 23** (issue #522). The three comparisons flip
> their LDAP/AD rows with a dated change-log line; Kerberos stays declined
> (D-1). Open and carried: T-332 (no per-name counter in front of JIT binds),
> the allow-list residual of T-300, and the items the W3 F4 review takes.

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

> **EXECUTED (partly) — G-5, W4: T23.5.1, 2026-10-04** (`212b314`, `9b90d7d`;
> Sonnet 5.5). The shared outbound dispatcher per **D-36**, with no behaviour
> change. `axiam_core::outbound`: `OutboundMessage`, `OutboundKind` (only
> `Webhook`; a new kind is one line in a macro that fixes its queue names, env
> vars and audit prefix), and the object-safe ports `OutboundPublisher` and
> `OutboundDeliverer` (one attempt → delivered, retry or dead-letter).
> `axiam-amqp` holds the generic topology, publisher, retry policy and consumer
> loop. The webhook kind keeps today's queues, declare arguments, env vars and
> its exact `WebhookMessage` wire bytes through a per-kind codec (a generic
> envelope would have broken in-flight messages and a rolling upgrade), pinned
> by tests; the webhook deliverer stays in `axiam-api-rest`. Tests: 26 new
> `axiam-amqp` tests (topology names and arguments byte for byte, retry env
> vars, the wire format both ways, the loop's ack, retry with TTL, DLQ, error
> mapping, unregistered kind, failed republish), 5 core tests, 6 api-rest
> tests; every existing webhook suite passes unchanged; OpenAPI byte-identical.
>
> What the plan did not anticipate. RabbitMQ refuses to redeclare a queue with
> other arguments, so the argument set is pinned too. The live-broker test stays
> `#[ignore]`d (no broker here); CI's e2e stack exercises delivery. The server's
> consumer supervisor loop is still inline, so each new kind copies about 30
> lines.

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
>
> **W2 F4, 2026-10-03:** [`security-review-phase23-w2-2026-10-03.md`](security-review-phase23-w2-2026-10-03.md).
> Thirteen findings, no merge blocker after fixes. Fixed on the branch, both
> wave-introduced in T23.3.1's storage layer: a directory configuration update
> without a new secret kept the stored bind secret while the URL, StartTLS,
> bind DN or trust anchors changed, so the write-only secret could have been
> redirected to an editor's host (**P23W2-01**, Medium, latent until
> T23.3.8 adds write routes), and a tenant delete whose transaction
> rolled back answered `204` (P23W2-02, Low). Filed: pre-existing tenant
> deletion that cascades to nothing else (P23W2-04, Medium, ilpanich/axiam#523),
> the `require_par` refusal coming only after the login hop (P23W2-03, Low,
> #524), the SMTP password kept across a host change (P23W2-05, Low, #525) and
> two informational gaps (P23W2-06/-07, #526). Accepted with reasons: the logout-hop residuals, T-300 and
> `ldap3`'s missing frame cap (both latent with no writer, and **binding
> preconditions on T23.3.8**), the directory timing residual, and the
> evidence script. The T23.1.8 and T23.3.2 surfaces held.
>
> **W3 F4, 2026-10-04:** [`security-review-phase23-w3-2026-10-04.md`](security-review-phase23-w3-2026-10-04.md).
> Fourteen findings, no merge blocker after fixes. Fixed on the branch, all
> wave-introduced or missed siblings of the wave's own fixes: directory linking
> left the account's **federation links** in place, a sign-in the directory never
> sees (**P23W3-01**, Medium, T-336 amended); **T-332 closed** with a
> per-(tenant, login name) failure counter for names AXIAM holds no account for,
> on the tenant's lockout policy (**P23W3-02**, Medium); **T-325 closed** by a
> request tracer that redacts every non-structural query value — the SAML handle
> and `RelayState`, and the pre-existing `state`, reset tokens and search terms
> (P23W3-03, Low); the §30 address guard's answers to a host name unified so they
> cannot map internal DNS (P23W3-04, Low, new **T-356**); JIT's lost race checks
> status before mapping (P23W3-05); CodeQL hygiene and two CSP pins (D-27
> confirmed: one setter, strictly narrower). The wave's own **D-23 fix of the
> Critical SP signature-confusion defect holds** under adversarial review
> (P23W3-06); its issue is filed only after the fix is on `main`, the maintainer
> deciding on a patch release and advisory first. Filed: the tenant email
> provider held to no outbound address policy (P23W3-11, Medium, ilpanich/axiam#529), unsigned and
> uncached IdP metadata (P23W3-07, #530), SHA-1 and DTDs accepted by the SP verifier
> (P23W3-08, #531), no limiter on `/oauth2/authorize` (P23W3-09, #532), certificates bound to
> users (P23W3-10, D-29, #533). Accepted with reasons: directory delete/disable leaving
> sessions and passkeys (documented, confirmed, audited), the missing
> multi-replica sweep guard, D-25 trusting directory-supplied addresses. Threat
> model **2.24.0 — 356 threats, 340 mitigated / 16 open**. **Binding on W4:**
> SLO (T23.2.4) verifies SP logout messages per node with the receiver's
> placement rule and SHA-2 only — never `verify_signed_xml` — and its routes are
> rate-limited; T23.2.5 refuses `encrypt_assertions` and an unparseable SP
> certificate and fetches SP metadata only through `guarded_fetch`; a second
> CSP-setting page must pass the D-27 pin; new ids start at T-357.

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
| D-16 | *Taken in T23.1.8 (Opus 5.5), 2026-10-03, accepted by the orchestrator.* The OP cookie (`Path=/oauth2/authorize`, and since D-11 `/t/{tenant_id}/oauth2/authorize`) never reaches `/oauth2/end_session`, so a logout without an `id_token_hint` `sid` could expire the cookie but not read it, and the session row it named survived (F4 residual P23W1-10). How does such a logout end that row? | **A hop to the `/logout` sub-path of the authorization endpoint the request came through**: `end_session` answers a request with no verified hint `sid` with a `302` to `/oauth2/authorize/logout?tenant_id=…` (bare) or `/t/{tenant_id}/oauth2/authorize/logout`, which RFC 6265 §5.1.4 path-match sends the cookie to. The hop looks the digest up in the request's tenant, revokes that one row, clears every cookie and continues exactly as `end_session` (exact-match `post_logout_redirect_uri` against the identified client's allow-list, `state` echoed only on a redirect that happens; the continuation never carries the hint). GET-only, public, rate-limited with the `end_session` preset (bucket `oauth2_end_session_cookie`, both mounts), in OpenAPI, and with **no back-channel fan-out**, so logout CSRF stays exactly what `end_session` already was. Threat **T-290**. Rejected: adding `/oauth2/end_session` to the cookie path list (widens the maintainer's D-11 layout to a second endpoint, and misses cross-site form POSTs); fanning out back-channel logout from the hop (any page could log a user out of every RP); a confirmation prompt (against B5); leaving the residual. Residual: a hinted logout whose browser cookie names a *different* session leaves that row with its cookies cleared |
| D-17 | *Taken by the orchestrator, 2026-10-03, on T23.1.5's escalation.* The request-time `fapi2` client-authentication re-check (`is_strong()`) ran at the token endpoint, token exchange and uma-ticket only; a `fapi2` row edited in the database to `client_secret_basic` or `client_secret_post` authenticated at PAR (`201`), introspection and revocation (`200`) with a correct secret | **The same rule runs at PAR, introspection and revocation**, after client authentication and before anything is pushed, revealed or revoked, through one extracted function (`fapi::enforce_client_authentication`, which `enforce_token_request` now calls first), so the endpoints cannot drift; the answer is the token endpoint's `invalid_client`. As with W1's "a `fapi2` row edited to `honour` is refused at authorize", the registration gate is not the only line. Rejected: accepting it as T-253's residual. Amends T-253 |
| D-18 | *Taken in T23.3.2 (Opus 5.5), 2026-10-03, accepted by the orchestrator.* How is a directory account marked, so that the bind path can find it and every local password door can refuse it? The `User` model had no `source` or `external_id` | **One optional column, `user.directory_external_id`** (schema **v71**, unique per tenant, any number of unset rows): the entry's `entryUUID` or decoded `objectGUID`; `Some` means the tenant's directory is the only authority for the account's password. It has exactly one writer, `UserRepository::mark_directory_account`, which in one transaction sets it, replaces `password_hash` with an Argon2id hash of 32 random bytes nobody holds, and deletes any OPAQUE record; `CreateUser` and `UpdateUser` have no such field, so neither the admin API nor SCIM can set or clear it. Both erasure paths clear it and Art. 15 export carries it. Directory accounts are created `Active` by T23.3.3 (the directory vouches for them; the email-verification grace rule is about local passwords). Rejected: a `source` enum plus an external id (two columns that can disagree) and a link row like `federation_link` (an extra read on every login, and a row that can be deleted on its own, silently turning a directory account back into a local one with whatever hash it holds) |
| D-19 | *Taken by the orchestrator, 2026-10-03, at the start of W3, on the W2 F4 review's §12.* The F4 review made T23.3.8 (Sonnet, "pattern work") responsible for closing **T-300** (a tenant-chosen directory host is not held to `guarded_fetch`'s private-address policy) and for a frame cap beneath `ldap3` before any write route ships. Both are security-bearing connector code: a resolver-and-pin connector beneath `ldap3`, with the TLS server name kept as the hostname, is exactly the kind of place §6 rule (a) gives to Opus | **The address guard and the frame cap ride T23.3.7 (Opus 5.5)**, which already owns the directory's remaining threat entries and contract §30, and which runs **before** T23.3.8: refuse loopback, link-local (including `169.254.169.254`), unspecified, multicast and AXIAM's own listener addresses after resolution, pin the resolved address for the connection, an operator-level allow-list for private ranges, a per-message frame cap; T-300 closes in that commit. T23.3.8 (Sonnet) then only calls `config::validate` and the guard on every write, surfaces the P23W2-01 rule as a `400`, and refuses a directory with `opaque_mode = required` (both ways) and IPv6-literal URLs. W3 order for G-3 is therefore T23.3.3 → T23.3.4 → T23.3.5 → T23.3.7 → T23.3.8 → T23.3.6 |
| D-20 | *Taken by the orchestrator, 2026-10-03, before T23.2.1.* §4 G-2's acceptance says "a tenant without the feature returns 404 on all three endpoints", but no per-tenant switch is designed; the `saml` Cargo feature is deployment-wide | **A layered setting `saml_idp_enabled`, default `false`**, exactly the shape of `sensitive_scopes_enabled` (organization default, tenant override, the same validation), added by T23.2.1. The metadata, SSO and SLO endpoints answer `404` when the deployment was built without `saml` **or** the tenant's effective setting is `false`, and the `404` does not distinguish the two. Rejected: "404 until the tenant registers an SP" (an SP administrator needs the IdP metadata *before* registering) |
| D-21 | *Taken by the orchestrator, 2026-10-03, on resuming T23.2.1.* The previous session landed T23.2.1's registry and D-20 (`8d0d875`, `5f4129c`) but not `CertificateType::SamlSigning` or the key at rest, and §4 G-2 *Signing key* leaves open the key algorithm, the extended key usage, where the key lives, who creates the credential and which CA signs it | **RSA-4096, `rsa-sha256`/`sha256`** (the XML-DSig pair every SP accepts; Ed25519 XML signatures are not deployed at SPs, and ECDSA is outside CLAUDE.md's pin). **`SamlSigning` profile:** keyUsage `digitalSignature` only (no `keyEncipherment`, even on RSA), extendedKeyUsage `id-kp-documentSigning` (RFC 9336) so no TLS verifier accepts it, no SANs. **Internal-only type:** the certificate issuance API, CSR signing, the bind endpoint, device login and mTLS refuse it, as they refuse `Server` where it authenticates nobody. **Custody:** a new per-tenant `saml_idp_credential` row (certificate PEM, the issuing CA's id, serial, SHA-256 fingerprint, `not_after`, a status `active` / `next` / `retired` with at most one `active` and one `next` per tenant enforced by the database) whose private key is sealed with AES-256-GCM under `pki_encryption_key` through `DatabaseCaKeyStore` — the CA custodian's database sealing — with the custody recorded on the row so a later custodian needs no migration. Not the configured CA custodian: the key signs on every assertion, a Vault round trip per sign-in is the wrong latency, and `VaultPki` cannot hold an exported key. The key is never returned by any API, `Debug`-redacted, and decrypted only into a `Zeroizing` buffer at signing time. **Not a `certificate` row and not on the wire:** the leaf lives in `saml_idp_credential` only, so no certificate-list or certificate-get response can carry it, and `SamlSigning` is excluded from the serialized `CertificateType` (no request deserializes to it, the OpenAPI enum is unchanged), so W3 makes no contract change; T23.2.8 (contract §29, Opus) decides whether the credential is exposed to SDKs. Retiring a credential removes it from metadata; no CRL entry is needed, since SPs pin the metadata certificate. The row goes with its tenant in the tenant-delete transaction. **Creation is explicit:** one service function issues the credential from a caller-named active signing CA of the tenant's organization (a CA of another organization, a non-signing or expired CA is refused); validity is the issuer-bounded leaf rule, at most 2 years. No lazy creation and no automatic rotation in W3: T23.2.5 adds the admin route and the metadata endpoint's behaviour without a credential; `next`/`retired` exist so rotation (publish `next` in metadata, then promote) needs no schema change. Rejected: storing it through the configured `CaKeyStore` (above), an ECDSA key (pin), and issuing it lazily on first SSO (an SP would see the IdP certificate change under it with no admin act) |
| D-22 | *Taken in T23.2.2 (Opus 5.5), 2026-10-03.* §4 G-2 makes the persistent **pairwise** `NameID` the default, and nothing in the workspace derives one: there is no pairwise-identifier helper, and no deployment secret meant for derivation (`axiam_core::secrets` holds encryption keys, the AMQP signing key and the GDPR audit pepper, each with its own purpose and lifecycle). The identifier must be stable per (tenant, SP entity id, user), unlinkable across SPs, not reversible to the user id, and must survive the IdP signing credential's rotation | **HMAC-SHA256 under a new, dedicated deployment key `saml_pairwise_key`** (logical name `axiam_core::secrets::SAML_PAIRWISE_KEY`, in `ALL_KEYS`, read from the secret provider like every 256-bit key; `AXIAM__AUTH__SAML_PAIRWISE_KEY` under the env provider): `NameID = hex(HMAC(k, "axiam/saml-pairwise/v1" ‖ 0x00 ‖ tenant_id ‖ user_id ‖ u32be(len(entity_id)) ‖ entity_id))`, 64 lower-case hex characters, written with `NameQualifier` = the IdP entity id and `SPNameQualifier` = the SP entity id. Keyed on the SP's **entity id**, not its row id, so deleting and re-registering an SP gives its users their identifiers back. Independent of the SAML signing key by construction, so rotating, retiring or re-issuing the credential changes nothing. The key is **optional and must never rotate**: without it a persistent-`NameID` sign-on is refused with `Responder` (never answered with a weaker identifier) and an `emailAddress` SP still works; rotating it, or losing it, gives every user a new, unknown account at every SP, which the constant's documentation says in those words. Nothing is stored, so there is no table, no migration, no erasure path and no export: erasing the user removes the only input that resolves to a person. `axiam_federation::saml_idp::pairwise_name_id` is the one implementation; the composition root (T23.2.3) reads the key into `SamlIdpIssuer::new`. Threat **T-312**. Rejected: a stored random value per (tenant, SP, user) — a new table in the tenant-delete transaction and both erasure paths, a write on every first sign-on with its own race, and nothing gained over a PRF unless the key is lost, which the key's documentation already treats as an outage; deriving from the SAML signing key (a rotation would re-key every account, the exact property required against); reusing `gdpr_pseudonym_pepper` or another existing key (one key serving two purposes with different rotation rules — the pepper's rotation is survivable for audit, this one's is not); a hash without a key (reversible by enumerating a tenant's user ids). Residual: the `SessionIndex` is the AXIAM session id (§4 G-2), the same at every SP of one sign-on, so SPs that compare notes can correlate concurrent sessions despite pairwise `NameID`s; recorded open on T-312 for T23.2.4 to decide whether SLO can map a per-SP index back |
| D-23 | *Taken by the orchestrator, 2026-10-03, on T23.2.2's finding.* T23.2.2 found a **Critical, pre-existing** defect in AXIAM's SAML **SP** verifier (`saml.rs`): `verify_signature` verifies only the first `ds:Signature` in the document, and `bind_signature_to_assertion` accepts any `Reference` naming the assertion whether or not that signature verified, so a document the upstream IdP signed for another purpose (a signed `LogoutRequest`/`LogoutResponse`, a signed error response) placed ahead of a forged assertion with a dummy signature provisions an arbitrary user. The wave rule says F4 files pre-existing findings as issues | **Fix it in W3, now, in T23.2.2's session (Opus 5.5)**, not at F4 and not as an issue: it is an authentication bypass on a shipped surface; G-2 itself adds a producer of exactly the gadget (an AXIAM IdP that will sign logout messages, T23.2.4), so W3 would widen it; and the probe test describing the attack is already on a public branch. The rule: a `ds:Signature` is accepted only as the enveloped child of the `Assertion` or of the `Response` root, any other `Signature` anywhere refuses the document; every accepted signature is verified individually against the IdP's certificate; the consumed assertion must be covered by a signature that verified (its own enveloped one); T-67 is amended (not reopened, since the fix lands in the same wave) and the CHANGELOG carries it under *Security*. The maintainer is told in the PR so that a patch release or advisory for deployments on `main` can be decided; the issue is filed after the fix is on `main`, not before |
| D-24 | *Taken in T23.2.3 (Opus 5.5), 2026-10-03.* How does a SAML `AuthnRequest` cross the login hop? The HTTP-POST binding arrives as a **cross-site form post**: the `SameSite=Lax` OP cookie is not sent on it, and the browser cannot be sent to `/login` and then re-post it. And how is `ForceAuthn` kept from inheriting P23W1-08 (an unbound hop marker)? | **Two legs and a server-side pending request.** The first leg (`GET`/`POST /saml/v2/{t}/sso`, `GET /sso/idp-initiated`) refuses everything decidable without a principal, then stores what it decided — SP, the ACS URL resolved against the registration, `RelayState`, `ForceAuthn`, `IsPassive`, the request `ID` and the **outbound instant** — in `saml_authn_request` (schema **v73**, ten-minute TTL) under the SHA-256 of a 256-bit opaque handle, and answers `303` to `/sso/continue?handle=…` with an `HttpOnly; Secure; SameSite=Lax` **binding cookie** scoped to the SSO path and named per handle (`axiam_saml_req_<16 hex of the handle digest>`, so concurrent sign-ons in one browser do not collide), whose digest the row also holds. The second leg requires that cookie (constant-time) before it reads a session or consumes anything, resolves the session from the OP cookie through the tenant-keyed digest lookup alone (the OP cookie is minted at `/saml/v2/{t}/sso` by every sign-in, D-11), applies `account_may_act`, and either issues (consuming the row on the X6 two-layer arbiter immediately before signing), answers (`NoPassive`; `AuthnFailed` on a return leg), or hops to `/login` with `return_to = /saml/v2/{t}/sso/continue?handle=…&axiam_login_hop=1` (the SAML arm of `validate_return_to_at`, re-run against the T23.1.3 list on both sides). **`ForceAuthn` is bound**: a session counts only if `authenticated_at > created_at` of the row; the marker only chooses between hopping again and answering, so forging it yields `AuthnFailed`, never an assertion. **Replay**: the row's `replay_key` (`{sp_id}:{request_id}`, or `idp:{row id}`) is UNIQUE per tenant and consumed rows are kept until expiry, which outlives the `IssueInstant` window (5 min back, 60 s skew forward). Rejected: replaying the request through the hop in the URL (the POST binding cannot, and a signed Redirect request's octets would have to survive the SPA untouched); a handle with no browser binding (a leaked link would sign in whoever opens it, T-322); deciding `ForceAuthn` by the marker (P23W1-08) |
| D-25 | *Taken in T23.2.3 (Opus 5.5), 2026-10-03, closing T-313.* May an email `NameID` carry an address AXIAM never verified? Most accounts never get `email_verified_at` (administrator, SCIM, directory, federation), and federated accounts are `PendingVerification` for life (T-160), so "verified only" would end email `NameID`s for nearly everyone; "always" lets a self-registration inside its grace period take over an email-keyed SP account | **An address is asserted when something vouches for it: `email_verified_at` is set, or the account is `Active`** — a state only the verification flow, an administrator, SCIM or the directory path put an account in, each of which proved or wrote the address. A `PendingVerification` account with an unverified address gets `InvalidNameIDPolicy` (`SamlIdpError::NameIdUnverified`) at an `emailAddress` SP, never a weaker identifier, and the `email` **attribute** is omitted for it under the same rule (an SP may key accounts on the attribute just as well). It keeps signing on wherever the `NameID` is the pairwise default. Implemented once, in `saml_idp` (`email_is_vouched_for`). Rejected: verified-only (above); a per-SP switch (a tenant administrator choosing to trust unverified addresses is the configuration T-313 is about); refusing the attribute rather than omitting it (the sign-on does not depend on it). Residual: a federated (JIT) account is pending for life, so an email-keyed SP refuses it until an administrator activates it |
| D-26 | *Taken in T23.2.3 (Opus 5.5), 2026-10-03.* D-3 makes IdP-initiated SSO a per-SP opt-in but designs no trigger, and §4 G-2 says nothing about which refusals an SP is told about. What starts an unsolicited response, and what does a refusal look like? | **Trigger: `GET /saml/v2/{t}/sso/idp-initiated?sp=<entity id>[&RelayState=…]`**, for AXIAM's own pages and bookmarks: refused with `403` when `Sec-Fetch-Site: cross-site` (a third-party page could otherwise sign a visitor in to an SP with a `RelayState` of its choosing), for an SP without `allow_idp_initiated`, a disabled SP, an SP asking for encryption, an unusable default ACS or an over-long `RelayState` — all before the hop, all error pages (an unsolicited failure response is no use to an SP). The response goes to the SP's default ACS with no `InResponseTo`. **Refusals, SP-initiated:** a request that has not shown it comes from the SP — undecodable, oversized, DTD-bearing, stale, malformed, unknown issuer, a failed or misplaced signature, a `Destination` mismatch, an ACS URL or index outside the registry, a non-POST `ProtocolBinding`, an over-long `RelayState`, a replayed `ID` — gets an **error page that posts nowhere** (`400`/`413`, generic text, nothing reflected); once the ACS is a registered POST endpoint, policy refusals are **posted** as unsigned status-only failures (`RequestDenied` for a disabled SP, `Responder` for encryption, `InvalidNameIDPolicy` for a conflicting `NameIDPolicy@Format`; after the hop `NoPassive`, `AuthnFailed`, `RequestDenied` for `allowed_groups`, `Responder` for a missing credential). An AuthnRequest naming a `Subject` is refused (not honoured); `RequestedAuthnContext` is not read (the assertion's class is the session's evidence, T-314). A signed request from an SP that registered no certificate is treated as unsigned (it cannot be evaluated); one that registered a certificate has every signature checked whether or not it requires signing. Rejected: a `POST` trigger with the API's CSRF token (the console has no launcher yet, and a top-level `GET` is what bookmarks and portals use); answering every refusal at the ACS (that posts attacker-chosen `RelayState`/`InResponseTo` to an SP on an unauthenticated request's word) |
| D-27 | *Taken in T23.2.3 (Opus 5.5), 2026-10-03.* The auto-post page needs an inline `submit()` and a `form-action` naming the ACS origin, but `SecurityHeadersMiddleware` overwrote every response's `Content-Security-Policy` with the global one (`script-src 'self'; form-action 'self'`); and the SSO routes need a rate-limit preset (§7 rule 6), and an indistinguishable `404` (D-20) | **The middleware writes the global policy only when the handler set none**; exactly one handler sets its own — the auto-post page's `default-src 'none'; script-src 'nonce-<per response>'; form-action <ACS origin>; frame-ancestors 'none'; base-uri 'none'`, stricter than the global policy everywhere but those two directives — with `Cache-Control: no-store`. **Rate limit:** the browser-endpoint preset `end_session_per_min` (human-driven, unauthenticated, 30/min/IP by default) on each route, with buckets of their own (`saml_idp_sso`, `saml_idp_sso_continue`, `saml_idp_sso_idp_initiated`) — no new configuration key. **D-20:** the tenant check (canonical UUID spelling, tenant exists, effective `saml_idp_enabled`) runs before the body is read, and every other method and sub-path under `/saml/v2/{t}` answers the same empty `404` via `default_service`, so no `405` tells a build with SAML from one without. Rejected: loosening the global CSP (`form-action *` everywhere); a new `saml_sso_per_min` key (one more knob for the same human-driven posture); `login_per_min` (10/min would throttle a NAT'd office that signs in to several SPs, the continue leg counting twice per hop). Residuals: Chrome applies `form-action` to redirects after the submission, so an SP whose ACS redirects to another origin before rendering needs that origin to be the ACS's; a flood tells a build with SAML from one without (429 vs 404) though not one tenant from another |
| D-28 | *Taken by the orchestrator, 2026-10-03, before T23.3.3, on the W2 F4 review's §12.* Does just-in-time provisioning (or the sync job) ever turn an **existing local account** into a directory account, and if an account is linked, what happens to what it already holds? `mark_directory_account` replaces the hash and deletes the OPAQUE record but revokes nothing, so the account's sessions, refresh tokens, passkeys and user certificates would keep working | **JIT and sync never link.** JIT creates an account only for a login name that matches no local account; if the entry the directory returns would collide with an existing account's username or email (case-folded as the repository folds them), the answer is the ordinary invalid-credentials failure, with the same dummy-verify timing, plus an audit row naming the collision (never the password) — so a directory administrator cannot take over a local account (e.g. `admin`) by creating a matching entry. The sync job (T23.3.5) never creates or links by name either; it acts only on accounts already carrying a `directory_external_id`. **Linking is an explicit administrator act**: T23.3.3 provides one service function, `link_local_account_to_directory`, that resolves the entry by the directory (not by a caller-supplied id), refuses an entry already linked to another account, and in one unit of work marks the account (`mark_directory_account`), **revokes all its sessions and OAuth2 refresh tokens, deletes its WebAuthn credentials and revokes its `User`-type certificates** (both authenticate without the directory deciding); TOTP enrolment is kept, since it is a second factor behind the directory password. It is audited. T23.3.8 exposes it as a route. Rejected: auto-linking by username or email (a directory-side takeover of local accounts), and keeping passkeys and certificates on a linked account (sign-in that the directory never sees, T-303's residual widened) |
| D-29 | *Taken by the orchestrator, 2026-10-03, on T23.3.3's report.* Three points D-18 and D-28 assumed and the tree contradicts: (1) **no certificate is bound to a user** — a certificate authenticates only as the service account it is bound to, so "revoke its `User`-type certificates" had no data model; (2) D-18 names exactly one writer of `directory_external_id`, but a half-made JIT account can only be avoided by creating it marked; (3) `User.email` is required and unique, and an AD entry may have no `mail` | (1) **Accepted for W3 as T23.3.3 built it**: linking revokes the tenant's still-active `User`-type certificates whose `metadata.user_id` names the account or whose subject CN equals its username or email, ignoring case (over-matching is the safe side of an administrator act that is audited); a real `user_id` binding on certificates (schema, issuance API, an SDK-visible field) is **filed as a follow-up issue**, not done in this phase. (2) **D-18 amended**: the marker has **two writers, both on the directory path only** — `mark_directory_account` (linking) and `create_directory_account` (JIT, one `CREATE` that is `Active`, marked and holding an unusable hash); neither `CreateUser` nor `UpdateUser`, the admin API nor SCIM can set or clear it. (3) **An entry without a usable email is refused** (the generic failure plus an `unusable_attributes` audit row): a synthesised placeholder address would be released as an email `NameID` (D-25 serves `Active` accounts) and as OIDC `email`. The *Directory* admin guide (T23.3.8) says so |
| D-30 | *Taken by the orchestrator, 2026-10-03, before T23.3.4, so the Sonnet task does not stall.* §4 G-3 says directory groups map "onto AXIAM groups by DN or by a mapping table", and leaves open where the mapping lives, whether a directory group name can match an AXIAM group by itself, which memberships the mapping owns, when it runs and what a failed group lookup does | **An explicit mapping table only**: `DirectoryConfig.group_mappings`, a list of `{ directory_group_dn, group_id }` (DN compared after RFC 4514 normalisation and case-folding of attribute types and values, at most 500 entries, every `group_id` a group of the same tenant, checked at write), in the `directory_config` row (next schema version). **No implicit match by name and no auto-created AXIAM groups**: a directory administrator who names a group `admins` gains nothing unless a tenant administrator mapped it. **The mapping owns only the memberships it made**: each `member_of` edge it writes is marked `source = directory`; on each application it adds the missing mapped memberships and removes directory-sourced ones no longer backed by the directory, and never touches a membership an administrator added by hand (and a manual membership of the same pair is left as it is). **Resolution**: `memberOf` (AD) or a reverse search `(&<group_filter>(<group_member_attribute>=<escaped user DN>))` under `group_base_dn` (OpenLDAP), the user DN entering the filter only through the RFC 4515 escape function; nested groups followed to `group_nesting_depth` with cycle detection and a hard cap of 1 000 groups per user; referrals never followed. **When**: on every successful directory sign-in (JIT and existing accounts) before the session is issued, so a removal in the directory takes effect at the next sign-in, and by the sync job (T23.3.5). **Fail closed**: a group lookup that fails or hits a cap refuses the sign-in with the directory-unavailable answer rather than keeping memberships that may have been revoked. Membership changes are audited. Rejected: matching by name (a directory-side privilege escalation), mapping by DN prefix or wildcard, and "keep the old memberships when the directory cannot be asked" |
| D-31 | *Taken by the orchestrator, 2026-10-03, before T23.3.5, so the Sonnet task does not stall.* §4 G-3 says "incremental by `modifyTimestamp`/`uSNChanged`, full reconciliation nightly, soft-delete on disappearance". AXIAM's `Deleted` status is an anonymised tombstone (erasure, not a soft delete); a vanished entry cannot be seen incrementally; the user filter is a login template, not an enumeration filter; and nothing says what "disabled in the directory" means on OpenLDAP or what happens when an entry comes back | **Soft-delete is `Inactive`**: a vanished or directory-disabled account is set `Inactive` (which `account_may_act` refuses on every path, passkeys and the OP cookie included, closing T-303's residual at the next run), its sessions and OAuth2 refresh tokens are revoked through the repositories, and its directory-sourced memberships are removed through the D-30 mapper; the row, its marker and its audit trail stay; never `Deleted`, never a hard delete. **Sync never re-enables and never creates or links** (D-28): an account the directory re-enables, or an entry that reappears, is re-enabled by an administrator; the audit row says so. **Full reconciliation (every 24 h)** looks up every account carrying `directory_external_id` by that id (`entryUUID` or the binary-escaped `objectGUID`, through the RFC 4515 escape function, exactly-one, under `base_dn`): found → update and map; not found → vanished. **Incremental (every `sync_interval_secs`)** searches `(<change attribute> >= <watermark>)` under `base_dn` and acts only on entries whose external id matches a marked account; on AD the watermark is `highestCommittedUSN` read from the rootDSE of the same server, and a change of server (`dsServiceName`) or a missing watermark falls back to a full run; deletions are left to the full run. **Disabled** means `userAccountControl` bit `0x2` on AD and, on OpenLDAP, `pwdAccountLockedTime` equal to ppolicy's permanent-lock value `000001010000Z` (amended after T23.3.5: any other value is a temporary failed-bind lockout, which an outsider can provoke by guessing at the directory, and since sync never re-enables it would have become a permanent deactivation — a denial of service; AD's own lockout lives in `lockoutTime`, not in `userAccountControl`, so AD was never affected). **Attribute updates** reuse T23.3.3's cleaners; a username or email change that would collide is skipped and audited, never applied. **Safety valve**: a full run that would deactivate more than 10 % of the tenant's directory accounts (and at least 5) applies nothing, is audited and reported as failed in job health — an empty search after a misconfiguration or an outage must not disable a company. **Errors** skip the tenant's run and change nothing. **State** (watermark, server, last full run, last result) in a per-tenant row (next schema version), deleted with the tenant. Runs on the existing cleanup scheduler, one tenant at a time, under the same deadlines and pool; only on tenants with an enabled directory. Rejected: `Deleted` (erases personal data the administrator never asked to erase), re-enabling from the directory (an attacker-controlled directory could revive accounts an administrator disabled), and enumerating with the login filter |
| D-32 | *Taken in T23.3.7 (Opus 5.5), 2026-10-04, accepted by the orchestrator.* D-19 asks for "an operator-level allow-list for private ranges", "AXIAM's own listener addresses" refused and "a per-message frame cap", and leaves open the allow-list's shape (SEC-107's `AXIAM__PKI__SSRF_ALLOWED_HOSTS` is a host list, and argues against CIDRs), what "own listener" means when the server knows only bind host and port, and how a cap can sit beneath `ldap3`, which does its own TLS | **(1) A network list, not a host list**: `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`, comma-separated CIDR blocks or single addresses, unset admits nothing, an unparseable entry ignored and logged at `error` (fails closed). Only addresses of the *private* class (RFC 1918, CGNAT, ULA) ever consult it; loopback, link-local, unspecified, multicast, special-purpose and the metadata endpoints inside private ranges (`fd00:ec2::254`, `100.100.100.200`) stay refused whatever it says. SEC-107's reasoning (a CIDR is widened by any DNS answer) holds for HTTP fetches whose response AXIAM processes; here the host is chosen per tenant in a multi-tenant deployment (an operator cannot enumerate every tenant's directory names, and an AD domain name resolves to a changing set of domain controllers), and inside a listed network the connector can do no more than a TLS handshake toward a host that must chain to the tenant's anchors before anything is sent — that residual is T-300's, stated. **(2) Own listeners by port on a local address**: the server knows its REST and gRPC bind host and port; an address is refused when its port is one of those and the address is this host's (loopback, or bindable by an unprivileged UDP socket — no packet sent); another replica's pod address and a Service forwarding to AXIAM are not recognisable, so the operator note says not to list AXIAM's own networks. **(3) The frame guard is a relay**: `ldap3 0.12` accepts an open stream only as a standard TCP or Unix socket and does its own TLS on the former, so a cap beneath it would see ciphertext; AXIAM performs StartTLS (one fixed 31-byte request, the reply through the guard) and the TLS handshake itself — same `ClientConfig`, server name the URL's host — and gives `ldap3` one end of a Unix socket pair (`ldapi`), a relay forwarding each directory message only after checking it: declared length ≤ the cap (`AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`, default 2 MiB, 64 KiB … 16 MiB) from the header, then well-formed, ≤ 16 levels deep, id + operation — which also closes `lber`'s unbounded recursion (T-331). `close` awaits the relay so a released permit never counts an open socket. A platform without Unix sockets refuses to connect (AXIAM ships on Linux only). **(4) The guard also refuses IPv6-literal URLs**, so T23.3.8's "refuse IPv6 literals" is the guard's answer surfaced as a `400`, and a stored one fails with that reason rather than a TLS name error. **(5) No safety-valve override in contract §30's first cut** (§30.3 rule 7 says why). Rejected: reusing the SEC-107 host list (unworkable per tenant), refusing all private ranges (breaks the feature), enumerating interfaces through a new dependency (the bind test needs none), a capped reader under `ldap3`'s TCP (sees ciphertext), forking `ldap3` |
| D-33 | *Taken by the orchestrator, 2026-10-04, on T23.3.8's question.* §30.3 rule 1 runs the address guard on every write, even one that does not change `url`, so a directory whose stored hostname has since been re-pointed to a refused address cannot even be switched off (`PATCH {"enabled": false}` is a `400`); only `DELETE` works, which also discards the configuration and its sync state | **The guard runs on every write whose resulting configuration is enabled**, and is skipped when the result is disabled, because a disabled directory opens no connection (the connect-time guard of T23.3.7 still applies to anything that does connect). `config::validate` still runs on every write, and the P23W2-01 rule is unchanged (moving the connection still needs the secret, enabled or not). Re-enabling runs the guard. Contract §30.3 rule 1 amended in place (no version bump: 1.54 is unreleased, and the change only admits a write the earlier text refused). Rejected: exempting only writes that touch no connection field (a disabled write that moves the URL would then skip the guard and be refused later anyway, so the simpler rule loses nothing) and leaving it (an administrator responding to an incident should be able to switch the connector off without deleting it) |
| D-34 | *Taken by the orchestrator, 2026-10-04, before W4 (lesson recorded at W3's start).* §6 assigns no task the SAML **SP registry's management routes** (create, read, list, update, delete of `SamlServiceProvider`, and the IdP signing-credential issue/list/retire/promote D-21 deferred), although T23.2.1 built the model and repository, T23.2.6's console page needs them, and contract §29 (T23.2.8) describes them | **They ride T23.2.5 (Sonnet 5.5)**, together with the IdP metadata endpoint and SP metadata import, because both write the same registry and both need `validate_saml_service_provider` on every write: T23.2.5 adds the routes under the §27 conventions (namespace `saml`, `Sensitive<T>` for nothing — the registry holds no secret — permissions `saml_sp:read`/`saml_sp:write`, human principals only, a rate-limit bucket), the credential routes with a **promote** verb (`next` → `active`, the old `active` → `retired`, one transaction) so T-309's rotation window can close, refuses `encrypt_assertions` while D-2's encryption is unimplemented and an SP certificate that does not parse (W3 F4 §15), fetches SP metadata only through `guarded_fetch`, and regenerates OpenAPI. **T23.2.8 (Opus) writes contract §29 first**, normative over those routes, so the order in W4 is T23.2.8's §29 → T23.2.5 → T23.2.6 (as G-3 ran T23.3.7's §30 before T23.3.8). The SP registry's threat-model element enters with the routes (§7 rule 2), written in T23.2.8. Rejected: giving the routes to T23.2.6 (a console task would then define an API) or to T23.2.8 (an Opus session spent on CRUD) |
| D-35 | *Taken by the orchestrator, 2026-10-04, at the start of W4.* §6 gives T23.2.9 "eleven SDK ports of §29" and T23.5.4 "optional receiver helper (seven SDKs)", but the SDKs live in eleven separate `ilpanich/axiam-<lang>-sdk` repositories, §7 rule 1 says ports follow **from the merge commit, never from a draft**, and no earlier wave ported its contract changes (1.53's §28.12, 1.54's §30 are still unported) | **The SDK fan-out is a post-merge step, not a wave task.** Inside the wave, T23.2.9 and T23.5.4 do the in-repository part only (OpenAPI regenerated, management registry, website, the contract's per-SDK test lists) and each opens **one tracking issue** per contract version listing, SDK by SDK, the operations, `Sensitive<T>` fields and portable tests to implement (§28.12, §29, §30, and the §31 receiver helper if G-5 adds one). The ports themselves run after the wave's PR merges, from its merge commit, in the SDK repositories, as a separate orchestrated fan-out the maintainer starts (it needs those repositories added to the session). Rejected: porting from the unmerged branch (§7 rule 1) and silently dropping the ports from the plan |
| D-36 | *Taken by the orchestrator, 2026-10-04, before T23.5.1, so the Sonnet task does not stall.* §6 says "extract the webhook dispatcher (`webhook.rs` queue, retry, backoff) into a shared outbound dispatcher with no behaviour change", but webhook delivery is not an in-process queue: `WebhookDeliveryService::emit` publishes to the durable `axiam.webhook` AMQP topology and `webhook_consumer` delivers once per (re)delivery, retries by per-message TTL + DLX, all inside `axiam-api-rest` (layer 6). SSF (G-5, `axiam-oauth2`, layer 4) and outbound SCIM (G-6) must enqueue deliveries, and layer 4 cannot reach layer 5 or 6 | **Ports in `axiam-core`, machinery in `axiam-amqp`, deliverers where their protocol lives, wiring in `axiam-server`.** `axiam-core` gains the envelope (`OutboundMessage { kind, tenant_id, target_id, payload, attempt, … }`, `OutboundKind` = `Webhook` now, room for `SsfPush`/`ScimOperation`) and two object-safe ports: `OutboundPublisher` (enqueue) and `OutboundDeliverer` (one attempt → delivered / retry / dead-letter). `axiam-amqp` holds the generic topology declaration, publisher and consumer loop, parameterised by kind, with the existing retry policy (`WebhookRetryConfig`'s env vars, `backoff_ttl_ms`, max attempts, DLQ) made generic. **No behaviour change for webhooks**: the webhook kind keeps exactly today's queue, exchange and DLQ names (renaming them would drop in-flight messages on upgrade), its signing (`X-Axiam-Timestamp`/`X-Axiam-Signature`), its `guarded_fetch` delivery and its env vars; each new kind gets its own sibling topology from the same declaration function. The webhook deliverer stays in `axiam-api-rest`; the SSF deliverer will live in `axiam-oauth2`, implementing the core port; `axiam-server` registers deliverers with the consumer. The layering table does not change. The minimal profile's in-process path when AMQP is off is G-8's work and plugs into the same ports. Rejected: moving webhooks into `axiam-oauth2` or SSF into `axiam-api-rest` (inverts the protocol placement), and one shared queue with a kind discriminator (renames the webhook topology, and one kind's backlog would delay the others) |
| D-37 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.4, closing the question D-22 left on T-312.* §4 G-2 makes `SessionIndex` the AXIAM session id "so SLO and the revocation feed revoke the same thing", which T23.2.2 shipped; it is the same value at every SP of one sign-on, so SPs that compare notes correlate a person's sessions despite pairwise `NameID`s (T-312). And single logout needs, for every logout, to know which SPs hold a session and which `NameID` and `SessionIndex` each was given — a pairwise `NameID` is an HMAC (D-22) and cannot be resolved back to a user without a record | **A per-SP random `SessionIndex`, recorded in a participant table `saml_sp_session`** (the next schema version free when T23.2.4 lands): one row per (tenant, session, SP) — `tenant_id`, `session_id`, `user_id`, `sp_id`, `sp_entity_id`, `name_id`, `name_id_format`, `session_index`, `created_at`, `expires_at` (the session's) — UNIQUE `(tenant_id, session_id, sp_id)` and UNIQUE `(tenant_id, sp_id, session_index)`. The index is 32 bytes from the OS CSPRNG, base64url without padding. **Written before signing**: the SSO continue leg writes the row (or reads back the existing one, so a second sign-on to the same SP within one session gets the same index — SAML Core §2.7.2.1 allows it) after consuming the handle and before `SamlIdpIssuer::issue`, which takes the index as an input (`SsoIssuance` gains it; the session id no longer reaches the XML); a failed write is `Responder` and no assertion, so no assertion exists that SLO cannot map back. **Mapped back** by the SLO endpoint (D-38) by (path tenant, the verified issuer's `sp_id`, `SessionIndex`) and only then compared with the request's `NameID` value and format, which must equal the row's — never by `NameID` alone, never by session id. The revocation feed is unchanged: SLO revokes the session the row names through `SessionRepository::invalidate`, which publishes that session id's hash, so §4 G-2's property still holds. The row holds the asserted `NameID`, personal data at an `emailAddress` SP: it is deleted when SLO revokes its session (D-39), swept once `expires_at` has passed or the session row is gone, deleted with its SP (in `delete`'s transaction), with its tenant (tenant-delete transaction) and by both erasure paths (by `user_id`). It holds no credential: a `SessionIndex` alone ends nothing, because a `LogoutRequest` must be signed (D-38). **T-312 closes when T23.2.4 lands**, with the residual that `AuthnInstant` is the session's `authenticated_at` at every SP — a timing correlation AXIAM cannot remove without misstating when the user authenticated (T-314). Rejected: an HMAC-derived index (one more deployment key, and SLO would still need the record to propagate and to resolve a pairwise `NameID`); keeping the session id (T-312); storing only a digest of the index (an IdP-initiated `LogoutRequest` must send it back to the SP) |
| D-38 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.4.* T-316 says a signed `LogoutRequest` or `LogoutResponse` is exactly the gadget D-23 defends against, and §6 gives T23.2.4 "SLO endpoint wired to session revocation" with no binding, verification, signing, refusal or rate-limit rule; the W3 F4 review (§15) asks for per-node verification with the receiver's placement rule, SHA-2 only, never `verify_signed_xml`, buckets of its own and the D-20 `404` | **The endpoint.** `/saml/v2/{t}/slo`, `GET` (HTTP-Redirect) and `POST` (HTTP-POST, form fields `SAMLRequest` or `SAMLResponse`, and `RelayState`), for both message kinds; no SOAP or artifact binding. D-20 and D-27 as for SSO: the tenant check before the body is read, every other method and sub-path the same empty `404` through `default_service`; a per-route governor with the `end_session_per_min` preset and the shared bucket `saml_idp_slo`. **Receiving** reuses T23.2.3's receiver unchanged: encoded value ≤ 96 KiB, document ≤ 64 KiB, the inflate cap, `refuse_markup_declarations` and `refuse_other_encodings` on the bytes before libxml, no recovery, no network. Then: `Version` 2.0; `ID` per `check_request_id`; `IssueInstant` at most five minutes old and 60 s ahead; `Issuer` present (entity format); `Destination` present and byte-equal to `idp_slo_url(base, tenant)`; a request's `NotOnOrAfter`, when present, in the future; `NameID` present — `BaseID` and `EncryptedID` refused, AXIAM issues neither; at most 32 `SessionIndex` elements (none means every session in which this SP holds that `NameID`). **Every message from an SP must be signed by its registered `sp_signing_cert_pem`** (SAML Profiles §4.4.4.1 requires logout messages to be authenticated, and through a browser a signature is the only way): HTTP-Redirect over the exact octets received (`SAMLRequest` or `SAMLResponse`, `RelayState`, `SigAlg`, each at most once), RSA with SHA-256/384/512 only — `RedirectQuery` generalised over the parameter name; HTTP-POST exactly one `ds:Signature`, the enveloped child of the root with one reference naming the root's `ID` (request.rs's placement rule, made a function over any root element), verified on that node by `verify_post_signature` (xmlsec, SHA-1 refused); a Redirect document carrying an enveloped signature refused; **`verify_signed_xml` is never called** (it checks the first signature only — the D-23 defect). An SP with no registered certificate cannot start a logout (its request gets the error page); its `LogoutResponse` to AXIAM's own request is accepted unsigned only to advance the chain (D-39) and is never counted as a confirmed logout. Anything refused before verification gets an error page that posts nowhere (D-26's rule: generic text, `400`/`413`, nothing reflected), and nothing an unverified message named is ever sent to an SP. **Replay**: a `LogoutRequest` `ID` is single-use per SP for longer than the `IssueInstant` window (`replay_key` `{sp_id}:{ID}`, UNIQUE per tenant in `saml_logout_run`, kept until the row expires, ten minutes). **AXIAM signs its own logout messages, narrowly.** With the tenant's active credential — an SP trusts one IdP key for everything, so a separate logout key in metadata would be trusted for assertions too and separates nothing — and in two cases only: a `LogoutRequest` for a session its holder ended (the D-39 trigger) or that a verified SP request ended, and a `LogoutResponse` replying to a verified `LogoutRequest` (`InResponseTo` its `ID`, status `Success` or `PartialLogout`). On HTTP-Redirect the signature is the detached query signature (`rsa-sha256` over `SAMLRequest`/`SAMLResponse`, `RelayState`, `SigAlg`), so **no XML signature exists to harvest**; on HTTP-POST it is enveloped exactly as the assertion's (root child, one reference to the root `ID`, exclusive c14n, `rsa-sha256`/`sha256`) and re-verified before it leaves. A reply to an unverified request is never sent, so no party without a session or an SP key can make the tenant's key sign anything (T-373). The outbound binding is the SP's registered `slo_binding` and the destination its `slo_url`, never a location from a message; the POST binding renders through the D-27 auto-post function (`form-action` = the `slo_url` origin), so `exactly_one_handler_sets_its_own_policy` still holds; an SP's `RelayState` (≤ 80 bytes, `check_relay_state`) is echoed to that SP only; no SLO parameter joins `KEPT_QUERY_PARAMETERS`. Rejected: unsigned logout messages (conforming SPs refuse them, and an unauthenticated logout lets anyone who learns an index sign a user out); a separate logout key (above); admitting unsigned requests from SPs without a certificate (same); the SOAP back channel (a new binding and an outbound client to every SP — T-380 records what its absence costs) |
| D-39 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.4.* §4 G-2 says SLO is "wired into the existing session-revocation path" and the acceptance wants "SLO revokes the session and the revocation feed shows it", but leaves open what a logout ends, how the other SPs of the session are told, in what order, what IdP-initiated logout is, and what happens to the OP cookie, which `/slo` cannot read (its path is `/saml/v2/{t}/sso`, D-11, and a cross-site POST would not carry a `SameSite=Lax` cookie anyway) | **A verified `LogoutRequest` ends whole AXIAM sessions** — the ones D-37 resolves, which an SP can name only when it participates in them with the `NameID` it was given (T-379) — not merely that SP's participation (SAML SLO semantics). For each session, in order: OIDC back-channel logout to its OIDC clients (`dispatch_backchannel_logout`, as `end_session` does for a signed hint — a verified request is a signed statement of which session), then `AuthService::logout` → `SessionRepository::invalidate`, which publishes to the revocation feed when it is on. No match is `Success`: the end state the SP asked for already holds. **Revoke first, then propagate**, so a chain that breaks never leaves an AXIAM session alive. **Propagation is front-channel and sequential**: every other SP of those sessions that registered an `slo_url` is sent a signed `LogoutRequest` carrying its own `NameID` and `SessionIndex`, one at a time through the browser, and its `LogoutResponse` at `/slo` advances the chain. The run lives in `saml_logout_run` (same schema version as D-37): tenant, initiator (an SP with its request `ID`, `RelayState` and `sp_id`, or the IdP), the queue of participant rows, the SHA-256 of the current outbound request's 256-bit random `ID`, a `partial` flag, the replay key and a ten-minute expiry; a response's `InResponseTo` is consumed once on the X6 arbiter (guarded `UPDATE` and read-back, as D-24) and must come from the SP the request went to (`Issuer`, and the signature when that SP registered a certificate). An SP without `slo_url`, an unsigned or non-`Success` answer, or the run cap (32 SPs) marks the run partial. The chain ends with a signed `LogoutResponse` to the initiating SP at its registered `slo_url` (`PartialLogout` when partial, else `Success`), or, for the IdP-initiated trigger, AXIAM's logged-out page (no post-logout redirect parameter in this cut). An SP that never answers strands the chain there; the AXIAM sessions are already gone, so only the remaining SPs' own sessions survive (T-380). The participant rows of the revoked sessions are deleted when the run ends or expires. Audit `saml_idp.logout` (initiator, SP, outcome, sessions ended, SPs told, partial — never a `NameID`). **The OP cookie**: `/slo` never reads it and never decides anything by it; every answer to a verified `LogoutRequest` clears every OP-cookie copy for the tenant and the API cookies (`clear_op_session_cookies`, as `/oauth2/authorize/logout` does), so the browser that carried the logout is signed out whichever session its cookie named. **IdP-initiated logout**: `GET /saml/v2/{t}/sso/logout`, under the SSO path so the OP cookie reaches it (as `/oauth2/authorize/logout` sits under the authorization endpoint), shared bucket `saml_idp_sso_logout`; `403` for `Sec-Fetch-Site: cross-site` (D-26's rule); it resolves the cookie through the tenant-keyed lookup, ends that session as above, clears the cookies, propagates over the session's participants and ends on the logged-out page; with no cookie or no live session it clears and shows the page. D-11's path list does not change; its documentation gains the third sub-path. **Not in this cut**: `/oauth2/end_session`, `/auth/logout`, an administrator's session revocation, a password reset and an account disable do not run a SAML chain (an API call cannot walk a browser through SPs); those SPs learn nothing until their own session ends or their next SSO request is refused (T-328) — T-380, Open and accepted. Rejected: SOAP back-channel logout (D-38); propagating before revoking; a fourth OP-cookie path for `/slo` (widens D-11, and the POST binding could not carry it anyway); fanning a SAML chain out of `end_session` (two logout protocols in one redirect sequence, for a later decision) |
| D-40 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.5.* §4 G-2 names an IdP metadata endpoint and D-21 says rotation publishes `next` before promoting, but nothing pins what the document carries, whether it is signed, what it answers when the tenant has no credential, its caching or its limiter | **`GET` and `HEAD /saml/v2/{t}/metadata`**, unauthenticated, `Content-Type: application/samlmetadata+xml`. One `EntityDescriptor`, `entityID` = `idp_entity_id(base, tenant)`; one `IDPSSODescriptor` with `protocolSupportEnumeration` the SAML 2.0 protocol URN and no `WantAuthnRequestsSigned` (it is per SP); one `KeyDescriptor use="signing"` per publishable credential, **`active` first, then `next`** (T-309), each an `X509Certificate` and nothing else; no `use="encryption"` key (AXIAM decrypts nothing); `NameIDFormat` persistent and emailAddress; `SingleSignOnService` for HTTP-Redirect and HTTP-POST at `idp_sso_url`; `SingleLogoutService` for both at `idp_slo_url`, **added by T23.2.4 in the commit that adds the route** — the document never advertises a route that does not exist. No `Organization`, `ContactPerson`, `Extensions`, `validUntil` or `cacheDuration`. Built from a fixed template with every value escaped through `saml_idp::xml`, the entity id and locations only from the three URL functions (T-307), which move out of the `saml`-gated module so §29's `get_idp` computes the same strings in every build. It reads `SamlIdpCredentialRepository::list` — never `get_active_sealed`. **Unsigned**: signing it with the key it publishes anchors nothing (whoever could swap the document could swap the key), and a signed `EntityDescriptor` is one more document under the tenant key (T-316); trust comes from TLS to the deployment's origin and, for a careful SP administrator, from comparing the SHA-256 fingerprint §29 shows. **No publishable credential (neither `active` nor `next`) answers the D-20 `404`**, empty and identical to a build without `saml`, a tenant with the setting off, an unknown tenant or a non-canonical id: a `503` would tell anyone that the tenant exists and serves SAML (T-326), and metadata without a key is of no use to an SP; the administrator sees readiness through §29's `get_idp`. **Caching**: `Cache-Control: public, max-age=3600` and a strong `ETag` (SHA-256 of the body; `If-None-Match` answers `304`); the rotation guidance is to issue `next`, wait at least this hour and the SPs' own metadata refresh interval, then promote. **Limiter**: a per-route governor with the `end_session_per_min` preset and the shared bucket `saml_idp_metadata`; every other method the D-20 `404`. Rejected: signed metadata (above); a `503` without a credential (above); publishing retired certificates (a retired key is destroyed and must stop being trusted); a `validUntil` (meaningless on an unsigned document) |
| D-41 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.5.* §4 G-2 asks for "metadata import (upload an SP metadata XML)", D-34 for fetching only through `guarded_fetch`, and the W3 F4 review (§15) says import "should not trust an unsigned document for anything security-bearing" — leaving open what import produces, what it takes from the document, how XML is refused, and what it does in a build without `saml` | **Import is a parse, never a write.** `POST /api/v1/tenants/{t}/saml/parse-sp-metadata` (§29 `saml.parse_sp_metadata`) takes exactly one of `metadata_xml` and `metadata_url` and returns a **draft** `SamlServiceProviderInput`, the SHA-256 fingerprints of the certificates it carries and a list of warnings; storing it is an ordinary `create_service_provider` or `update_service_provider`, through the validator and §29's write-time rules, so there is one write path and the administrator sees exactly what will be trusted before anything is. **A URL** must be `https` and is fetched only through `axiam_pki::ssrf::guarded_fetch` with `allow_private = false` (IP-pinned, private, loopback, link-local and metadata addresses refused, every redirect hop re-validated, its timeout and 5 MiB transport cap), then held to the 512 KiB document cap the SP side uses; one fetch per call, no credentials, and **no periodic refresh** — AXIAM never re-reads an SP's metadata on its own. A failure answers a generic category (`metadata_url refused`, `metadata fetch failed`, `not SAML service-provider metadata`) and never the response body, the status line or the resolved address (T-356's lesson), so the route cannot read internal responses. **An upload** is `metadata_xml`, at most 512 KiB (the route's JSON limit raised for that route alone). **XML** is refused as the receiver refuses it: `refuse_markup_declarations` and `refuse_other_encodings` on the bytes before any parser (no DTD, so no entity, external or internal), then `samael`'s metadata types, which open no network. Exactly one `EntityDescriptor` with one `SPSSODescriptor` supporting SAML 2.0; an `EntitiesDescriptor` aggregate is refused. **Taken, as a draft only**: `entityID`; the HTTP-POST `AssertionConsumerService` endpoints with `index` and `isDefault` (other bindings dropped, with a warning); one `SingleLogoutService`, HTTP-Redirect preferred over HTTP-POST (no harvestable signature, D-38); the first `KeyDescriptor` with `use="signing"` or no `use` as `sp_signing_cert_pem` (more → warning); `use="encryption"` as `sp_encryption_cert_pem`, with `encrypt_assertions` left `false` (D-2, refused at write); `AuthnRequestsSigned="true"` as `want_authn_requests_signed`; the first of persistent / emailAddress among `NameIDFormat`s; `display_name` from `OrganizationDisplayName`, else the entity id's host. **Trusted from an unsigned document: nothing.** A `ds:Signature` in the document is not evaluated — there is no anchor to evaluate it against, and evaluating it against a certificate the same document carries is circular — and its presence is reported as the warning "metadata signature not verified"; `validUntil` and `cacheDuration` are ignored; the draft is a suggestion the administrator submits. Audit `saml_sp.metadata_parsed` (source, the URL's host only, outcome) and refusals with their category. **Without `saml` in the build** the route answers `503 service_unavailable` (`samael` is behind the feature); it is compiled in every build, so it is in `openapi.json`. Permission `saml_sp:write` (it makes an outbound request), §29's write bucket. Rejected: import-and-create in one call (stores unsigned content nobody has seen, and a second write path); evaluating the document's own signature (circular); periodic refresh from a URL (a compromised SP host would silently swap the ACS list and the certificates) |
| D-42 | *Taken in T23.2.8 (Opus 5.5), 2026-10-04, before T23.2.5, completing D-34.* D-34 gives T23.2.5 the registry and credential routes but leaves open whether they exist in a build without `saml` (the committed `openapi.json` is exported with `--no-default-features`, so a gated route reaches no SDK), whether they depend on `saml_idp_enabled`, which writes are refused beyond the validator, and the credential verbs' exact semantics | **Compiled in every build, independent of `saml_idp_enabled`.** The registry is plain data, its validator is outside the feature (T23.2.1) and the credential service is `axiam-pki`'s, so the eleven §29 routes live in the main `ApiDoc` and the management registry; only `parse_sp_metadata` answers `503` without `saml` (D-41). An administrator registers SPs and issues the credential before switching the IdP on — D-20's own reasoning. **Write-time refusals**, after `validate_saml_service_provider`, each `400 validation_error` naming the rule: `encrypt_assertions: true` ("not supported yet", D-2 — the SSO endpoint would answer `Responder` to every sign-on); an `sp_signing_cert_pem` that `axiam_federation::cert::pem_cert_to_der` — the SSO endpoint's own decoder — refuses, or whose public key no verifier AXIAM runs can use (RSA under 2 048 bits; anything but RSA or ECDSA on P-256, P-384 or P-521; ECDSA verifies the POST binding only, which §29 says); a changed `entity_id` on `update` ("register a new service provider": D-22 keys every pairwise `NameID` on it, and D-37's rows name it); an `allowed_groups` entry that is not a group of the tenant. An expired SP certificate is not refused (SAML metadata keys are trusted as keys, not by validity); the draft warns. `slo_url` without a signing certificate is accepted (IdP-initiated logout can still reach it), and §29 says SP-initiated logout needs the certificate. **Credentials.** `issue_idp_credential { issuer_ca_id, slot, validity_days }` (1–730, default 365) into an empty `active` or `next` slot (`409` otherwise), with the issuing scope taken from the principal (a tenant principal reaches only its tenant's CA). `promote_idp_credential/{credential_id}`: the id must be the tenant's current `next` (`409` if not — a stale page cannot promote something else) and inside its validity window (`409`); **one transaction** retires the old `active` (its key destroyed in the same write) and makes `next` `active` — a repository method of its own, since two calls would leave a window with two signers or none. `retire_idp_credential/{credential_id}` is allowed on `next` and on `active` — the only way to stop a leaked key signing (T-306) — and retiring the `active` with no successor stops SAML sign-on for the tenant at once, which the console must say before it asks; retiring a retired credential answers it unchanged and writes no audit row. Responses carry the credential's public facts only: a response type of their own, no key, no ciphertext, no `key_custody`. **Permissions**: `saml_sp:read` (`get_idp`, the SP reads, `list_idp_credentials`), `saml_sp:write` (SP writes, `parse_sp_metadata`) and **`saml_idp:credential`** for the three credential writes, kept apart because one of them changes or stops sign-on at every SP of the tenant at once (T-364). Human principals only (a service-account token is `403`), the caller's own tenant only (another tenant's id `403`), as §30. **Limiter**: a new key `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN` (default 30, per IP, one bucket per route) on the writes; reads unlimited, as other administrator reads. Audit rows `saml_sp.created`, `saml_sp.updated` (names of the changed fields, `acs_changed`, `certificate_changed`), `saml_sp.deleted`, `saml_idp.credential_issued`, `saml_idp.credential_promoted` and `saml_idp.credential_retired` (ids, slot, fingerprint). Contract §29 is normative over all of it. Rejected: gating the routes on `saml` (no SDK could reach them) or on `saml_idp_enabled` (D-20's reasoning); promote as two calls; refusing to retire the active credential (it is the incident response T-306 needs); reusing `directory_admin_per_min` (a shared budget under a wrong name) |
| D-43 | *Taken by the orchestrator, 2026-10-04, on T23.2.5's report.* §29.3 rule 9 said a service-account token on the `saml` namespace is `403`, but the shared human-only extractor answers `401` for every human-only family (S-9), §30 says `401`, and `m2m_management_test` pins `401` across every human-only route | **`401`, as everywhere else**: §29.3 rule 9 amended in place (1.55 is unreleased; no SDK has ported it); T23.2.5's tests and CHANGELOG already say `401`. Rejected: a per-namespace `403` (a second refusal shape SDKs would have to special-case for one namespace) |

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
